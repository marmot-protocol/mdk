use cgka_traits::error::PeelerError;

/// Errors from Nostr DTO conversion. Trait methods map these into
/// [`PeelerError`] so the engine can classify stale/decrypt cases normally.
#[derive(Debug, thiserror::Error)]
pub enum NostrPeelerError {
    #[error("malformed Nostr event: {0}")]
    Malformed(String),
    #[error("unsupported Nostr kind: {0}")]
    UnsupportedKind(u64),
    #[error("missing required Nostr tag: {0}")]
    MissingTag(String),
}

pub(crate) fn to_peeler_error(err: NostrPeelerError) -> PeelerError {
    match err {
        NostrPeelerError::Malformed(msg) => PeelerError::Malformed(msg),
        NostrPeelerError::UnsupportedKind(kind) => {
            PeelerError::Malformed(format!("unsupported Nostr kind: {kind}"))
        }
        NostrPeelerError::MissingTag(tag) => PeelerError::Malformed(format!("missing tag {tag}")),
    }
}
