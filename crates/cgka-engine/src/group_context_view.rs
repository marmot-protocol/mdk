//! Concrete [`GroupContext`] view returned by `Engine::group_context`.
//!
//! Eagerly evaluates the group's epoch and a fixed set of well-known
//! exporter secrets at construction time; subsequent queries are cheap
//! local lookups. Unknown labels return `None`.
//!
//! For peelers' use, prefer `GroupContextSnapshot::from_context(view, &[..])`
//! which materializes an isolated copy with only the labels a specific
//! peeler is permitted to see.
//!
//! ## Length contract
//!
//! `exporter_secret(label, length)` returns the cached secret when the
//! cached bytes are at least `length` long, truncating only the trailing
//! tail (caching N bytes covers any caller asking for ≤ N). Callers asking
//! for more bytes than were cached at construction time get `None` rather
//! than a silent prefix — a fresh `MLS-Exporter` derivation must instead
//! happen via the engine, which has the live OpenMLS group.

use cgka_traits::group_context::{GroupContext, SecretBytes};
use cgka_traits::types::EpochId;
use std::collections::HashMap;

pub struct GroupContextView {
    epoch: EpochId,
    secrets: HashMap<String, SecretBytes>,
    transport_group_id: Option<Vec<u8>>,
}

impl GroupContextView {
    pub(crate) fn new(
        epoch: EpochId,
        secrets: HashMap<String, SecretBytes>,
        transport_group_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            epoch,
            secrets,
            transport_group_id,
        }
    }
}

impl GroupContext for GroupContextView {
    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn exporter_secret(&self, label: &str, length: usize) -> Option<SecretBytes> {
        let stored = self.secrets.get(label)?;
        if stored.len() < length {
            // Caller wants more than we cached. Returning a prefix would
            // silently violate the API contract (which is an MLS-Exporter
            // request, not a slice request). Fail loudly.
            return None;
        }
        Some(SecretBytes::new(
            stored.iter().take(length).copied().collect(),
        ))
    }

    fn transport_group_id(&self) -> Option<Vec<u8>> {
        self.transport_group_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGINE_EXPORTER_LABEL: &str = "marmot/group-event";

    fn context() -> GroupContextView {
        GroupContextView::new(
            EpochId(7),
            HashMap::from([(
                ENGINE_EXPORTER_LABEL.into(),
                SecretBytes::new((0u8..32).collect()),
            )]),
            None,
        )
    }

    #[test]
    fn exporter_secret_returns_prefix_when_caller_asks_for_less() {
        let ctx = context();
        let prefix = ctx.exporter_secret(ENGINE_EXPORTER_LABEL, 16).unwrap();
        assert_eq!(prefix.len(), 16);
        assert_eq!(prefix.as_slice(), &(0u8..16).collect::<Vec<_>>());
        let full = ctx.exporter_secret(ENGINE_EXPORTER_LABEL, 32).unwrap();
        assert_eq!(&full[..16], &prefix[..]);
    }

    #[test]
    fn exporter_secret_returns_none_when_caller_asks_for_more_than_cached() {
        let ctx = context();
        assert!(
            ctx.exporter_secret(ENGINE_EXPORTER_LABEL, 33).is_none(),
            "over-length request must be rejected, not silently truncated"
        );
    }

    #[test]
    fn exporter_secret_returns_none_for_unknown_label() {
        let ctx = context();
        assert!(ctx.exporter_secret("unknown-label", 32).is_none());
    }
}
