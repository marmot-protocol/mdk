//! C mirrors of cached public event previews.

use marmot_uniffi::{PublicEventPreviewFfi, PublicEventPreviewStateFfi};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Local state of one referenced public event.
    MarmotPublicEventPreviewState from PublicEventPreviewStateFfi {
        /// `event_json` is non-NULL and `fetched_at` is set.
        Present,
        /// The author published a NIP-09 deletion request for the event.
        Deleted,
        /// Nothing is cached. Not durable: a refresh may still find it.
        Missing,
        /// Not a `note`, `nevent`, `naddr` or hex event ID.
        Unsupported,
    }
}

c_mirror! {
    /// One result per requested reference, in request order.
    MarmotPublicEventPreview from PublicEventPreviewFfi,
    free marmot_public_event_preview_free,
    list(MarmotPublicEventPreviewList, marmot_public_event_preview_list_free) {
        /// The reference exactly as the caller passed it.
        str reference,
        copy state: MarmotPublicEventPreviewState,
        /// The signature-verified event as NIP-01 JSON; NULL unless `Present`.
        opt_str event_json,
        /// When a relay last confirmed the event, in Unix seconds.
        opt_copy has_fetched_at/fetched_at: u64,
    }
}
