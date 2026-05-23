//! Engine-internal view of a group's live state plus a value-type snapshot
//! that crosses the peeler boundary.
//!
//! Peeler calls use [`GroupContextSnapshot`], a value type the engine
//! materializes before each wrap or peel operation. This avoids borrowing
//! live engine state across async trait calls.
//!
//! The [`GroupContext`] trait stays as an engine-internal abstraction (so
//! `CgkaEngine::group_context` can return something richer than a snapshot
//! if the application layer asks). It must **not** cross the peeler
//! interface.

use crate::types::EpochId;
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

/// Heap-owned secret bytes that are wiped when dropped.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Engine-internal live view of a group. Application code can query this via
/// `CgkaEngine::group_context`. Peeler code must not — the peeler uses
/// [`GroupContextSnapshot`].
pub trait GroupContext: Send + Sync {
    fn epoch(&self) -> EpochId;
    fn exporter_secret(&self, label: &str, length: usize) -> Option<SecretBytes>;
    fn transport_group_id(&self) -> Option<Vec<u8>>;
}

/// Value-type snapshot of a [`GroupContext`] carrying exactly the secrets a
/// specific peeler is authorized to see.
///
/// Constructed fresh per peeler call. The `labels` argument to
/// [`GroupContextSnapshot::from_context`] names which exporter secrets the
/// snapshot should materialize — per-peeler isolation comes for free.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GroupContextSnapshot {
    epoch: EpochId,
    exporter_secrets: HashMap<String, SecretBytes>,
    transport_group_id: Option<Vec<u8>>,
}

impl GroupContextSnapshot {
    /// Materialize a snapshot from a live [`GroupContext`], copying only the
    /// exporter secrets named in `labels`. Default secret length is 32 bytes.
    pub fn from_context(ctx: &dyn GroupContext, labels: &[&str]) -> Self {
        let mut exporter_secrets = HashMap::new();
        for label in labels {
            if let Some(secret) = ctx.exporter_secret(label, 32) {
                exporter_secrets.insert((*label).to_string(), secret);
            }
        }
        Self {
            epoch: ctx.epoch(),
            exporter_secrets,
            transport_group_id: ctx.transport_group_id(),
        }
    }

    /// Hand-build a snapshot. Useful in tests / harness.
    pub fn new(
        epoch: EpochId,
        exporter_secrets: HashMap<String, Vec<u8>>,
        transport_group_id: Option<Vec<u8>>,
    ) -> Self {
        let exporter_secrets = exporter_secrets
            .into_iter()
            .map(|(label, secret)| (label, SecretBytes::new(secret)))
            .collect();
        Self {
            epoch,
            exporter_secrets,
            transport_group_id,
        }
    }

    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    pub fn exporter_secret(&self, label: &str) -> Option<&[u8]> {
        self.exporter_secrets
            .get(label)
            .map(|secret| secret.as_slice())
    }

    pub fn transport_group_id(&self) -> Option<&[u8]> {
        self.transport_group_id.as_deref()
    }
}

impl fmt::Debug for GroupContextSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupContextSnapshot")
            .field("epoch", &self.epoch)
            .field("exporter_secret_count", &self.exporter_secrets.len())
            .field("transport_group_id", &self.transport_group_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_debug_redacts_exporter_secret_bytes() {
        let mut exporter_secrets = HashMap::new();
        exporter_secrets.insert("test/exporter".to_owned(), b"super secret bytes".to_vec());
        let snapshot = GroupContextSnapshot::new(EpochId(7), exporter_secrets, None);

        let rendered = format!("{snapshot:?}");

        assert!(!rendered.contains("super secret bytes"));
        assert!(rendered.contains("exporter_secret_count"));
    }
}
