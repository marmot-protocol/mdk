//! Cached previews of public Nostr events referenced from message content.
use crate::{Marmot, MarmotKitError};

/// Local state of one referenced public event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PublicEventPreviewStateFfi {
    /// `event_json` and `fetched_at` are set.
    Present,
    /// The author published a NIP-09 deletion request for the event.
    Deleted,
    /// Nothing is cached. Not durable: a refresh may still find it.
    Missing,
    /// Not a `note`, `nevent`, `naddr` or hex event ID.
    Unsupported,
}

/// One result per requested reference. `event_json` and `fetched_at` are set
/// exactly when `state` is `Present`.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicEventPreviewFfi {
    /// The reference exactly as the caller passed it.
    pub reference: String,
    pub state: PublicEventPreviewStateFfi,
    /// The signature-verified event as NIP-01 JSON.
    pub event_json: Option<String>,
    /// When a relay last confirmed the event, in Unix seconds.
    pub fetched_at: Option<u64>,
}

impl From<marmot_app::PublicEventPreviewRead> for PublicEventPreviewFfi {
    fn from(value: marmot_app::PublicEventPreviewRead) -> Self {
        use marmot_app::PublicEventPreview as Preview;
        let (state, event_json, fetched_at) = match value.preview {
            Preview::Present {
                event_json,
                fetched_at,
            } => (
                PublicEventPreviewStateFfi::Present,
                Some(event_json),
                Some(fetched_at),
            ),
            Preview::Deleted => (PublicEventPreviewStateFfi::Deleted, None, None),
            Preview::Missing => (PublicEventPreviewStateFfi::Missing, None, None),
            Preview::Unsupported => (PublicEventPreviewStateFfi::Unsupported, None, None),
        };
        Self {
            reference: value.reference,
            state,
            event_json,
            fetched_at,
        }
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Network-free cached previews for first-frame rendering: one result per
    /// reference, in input order, duplicates included. Accepts at most 16
    /// references (`note`, `nevent`, `naddr` or hex event ID, with or without
    /// `nostr:`). A cold call may open the account's encrypted cache, so warm
    /// it off the UI thread. Author profiles come from
    /// `cached_identity_projections`.
    pub fn cached_public_event_previews(
        &self,
        account_ref: String,
        references: Vec<String>,
    ) -> Result<Vec<PublicEventPreviewFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .cached_public_event_previews(&account_ref, &references)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Fetch one referenced event from relays when it is missing or stale,
    /// then return its local state. An event-ID preview never refetches once
    /// every relay answered the fetch that cached it; otherwise, and for
    /// `naddr` previews, it refetches after 30 minutes. Calls within 30
    /// seconds of a finished fetch for the same reference return local state.
    /// A failed or empty fetch keeps prior content.
    pub async fn resolve_public_event_preview(
        &self,
        account_ref: String,
        reference: String,
    ) -> Result<PublicEventPreviewFfi, MarmotKitError> {
        Ok(self
            .runtime
            .resolve_public_event_preview(&account_ref, &reference)
            .await?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use marmot_account::AccountHome;
    use marmot_app::MarmotApp;

    use super::*;

    #[tokio::test]
    async fn cached_public_event_previews_round_trip_to_ffi() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "ws://127.0.0.1:1");
        let runtime = app.runtime();
        let marmot = Marmot { app, runtime };
        let references = vec!["ab".repeat(32), "garbage".to_owned(), "ab".repeat(32)];
        let reads = marmot
            .cached_public_event_previews("alice".into(), references.clone())
            .unwrap();
        assert_eq!(
            reads
                .iter()
                .map(|read| (read.reference.clone(), read.state))
                .collect::<Vec<_>>(),
            vec![
                (references[0].clone(), PublicEventPreviewStateFfi::Missing),
                (
                    references[1].clone(),
                    PublicEventPreviewStateFfi::Unsupported
                ),
                (references[2].clone(), PublicEventPreviewStateFfi::Missing),
            ]
        );
        assert!(
            reads
                .iter()
                .all(|read| read.event_json.is_none() && read.fetched_at.is_none())
        );
        assert!(matches!(
            marmot.cached_public_event_previews(
                "alice".into(),
                vec!["ab".repeat(32); marmot_app::MAX_PUBLIC_EVENT_REFERENCES + 1],
            ),
            Err(MarmotKitError::InvalidPublicEventReferences { max_references: 16 })
        ));

        let present = PublicEventPreviewFfi::from(marmot_app::PublicEventPreviewRead {
            reference: "r".into(),
            preview: marmot_app::PublicEventPreview::Present {
                event_json: "{}".into(),
                fetched_at: 7,
            },
        });
        assert_eq!(present.state, PublicEventPreviewStateFfi::Present);
        assert_eq!(present.event_json.as_deref(), Some("{}"));
        assert_eq!(present.fetched_at, Some(7));
        marmot.runtime.shutdown_and_close().await.unwrap();
    }
}
