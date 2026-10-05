//! Verified public event cache operations shared by Swift and Kotlin hosts.
use crate::conversions::UserProfileMetadataFfi;
use crate::{Marmot, MarmotKitError};

/// Which canonical identity a [`PublicEventCacheKeyFfi`] carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PublicEventCacheKeyTypeFfi {
    /// `event_id_hex` is set; the other fields are `None`.
    EventId,
    /// `author_pubkey_hex`, `kind` and `identifier` are set; `event_id_hex` is `None`.
    Coordinate,
}

/// Canonical cache identity. Relay hints and nevent author/kind hints are never
/// part of it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicEventCacheKeyFfi {
    pub key_type: PublicEventCacheKeyTypeFfi,
    pub event_id_hex: Option<String>,
    pub author_pubkey_hex: Option<String>,
    pub kind: Option<u32>,
    pub identifier: Option<String>,
}

/// Local state of one reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PublicEventCacheStateFfi {
    /// `preview` is set.
    Present,
    /// `deletion` is set: authenticated NIP-09 evidence from the author.
    AuthoritativeDeleted,
    /// Nothing is known locally. Not durable negative truth.
    Missing,
    /// Account lifecycle work is in progress; retry. Never a miss.
    Busy,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PublicEventPreviewFfi {
    pub event_json: String,
    pub received_at: u64,
    pub refresh_recommended: bool,
    pub author_profile: Option<UserProfileMetadataFfi>,
    pub projection_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PublicEventDeletionFfi {
    pub deletion_event_json: String,
    pub received_at: u64,
    pub projection_version: u32,
}

/// One result per requested reference. Invariant: `preview` is set exactly
/// when `state` is `Present`, `deletion` exactly when it is
/// `AuthoritativeDeleted`; both are `None` for `Missing` and `Busy`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PublicEventCacheReadFfi {
    pub key: PublicEventCacheKeyFfi,
    pub state: PublicEventCacheStateFfi,
    pub preview: Option<PublicEventPreviewFfi>,
    pub deletion: Option<PublicEventDeletionFfi>,
}

impl From<marmot_app::PublicEventPreview> for PublicEventPreviewFfi {
    fn from(value: marmot_app::PublicEventPreview) -> Self {
        Self {
            event_json: value.event_json,
            received_at: value.received_at,
            refresh_recommended: value.refresh_recommended,
            author_profile: value.author_profile.map(Into::into),
            projection_version: value.projection_version,
        }
    }
}

impl From<marmot_app::PublicEventDeletion> for PublicEventDeletionFfi {
    fn from(value: marmot_app::PublicEventDeletion) -> Self {
        Self {
            deletion_event_json: value.deletion_event_json,
            received_at: value.received_at,
            projection_version: value.projection_version,
        }
    }
}

impl From<marmot_app::PublicEventCacheKey> for PublicEventCacheKeyFfi {
    fn from(value: marmot_app::PublicEventCacheKey) -> Self {
        match value {
            marmot_app::PublicEventCacheKey::EventId { event_id_hex } => Self {
                key_type: PublicEventCacheKeyTypeFfi::EventId,
                event_id_hex: Some(event_id_hex),
                author_pubkey_hex: None,
                kind: None,
                identifier: None,
            },
            marmot_app::PublicEventCacheKey::Coordinate {
                kind,
                author_pubkey_hex,
                identifier,
            } => Self {
                key_type: PublicEventCacheKeyTypeFfi::Coordinate,
                event_id_hex: None,
                author_pubkey_hex: Some(author_pubkey_hex),
                kind: Some(kind),
                identifier: Some(identifier),
            },
        }
    }
}

impl From<marmot_app::PublicEventCacheRead> for PublicEventCacheReadFfi {
    fn from(value: marmot_app::PublicEventCacheRead) -> Self {
        use marmot_app::PublicEventCacheResult as CacheResult;
        let (state, preview, deletion) = match value.result {
            CacheResult::Present(preview) => (
                PublicEventCacheStateFfi::Present,
                Some(preview.into()),
                None,
            ),
            CacheResult::AuthoritativeDeleted(deletion) => (
                PublicEventCacheStateFfi::AuthoritativeDeleted,
                None,
                Some(deletion.into()),
            ),
            CacheResult::Missing => (PublicEventCacheStateFfi::Missing, None, None),
            CacheResult::Busy => (PublicEventCacheStateFfi::Busy, None, None),
        };
        Self {
            key: value.key.into(),
            state,
            preview,
            deletion,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Network-free, ordered cached reads for first-frame state: one result per
    /// input (at most 16, duplicates included). Invalid input is an error;
    /// lifecycle contention returns `Busy` rows without waiting.
    pub fn cached_public_event_previews(
        &self,
        account_ref: String,
        references: Vec<String>,
    ) -> Result<Vec<PublicEventCacheReadFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .cached_public_event_previews(&account_ref, &references)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Validate and retain a bounded batch of signed candidates (targets,
    /// NIP-09 deletions, the selected author's kind-0). No relay request.
    pub async fn cache_public_event_preview(
        &self,
        account_ref: String,
        reference: String,
        candidates: Vec<String>,
    ) -> Result<PublicEventCacheReadFfi, MarmotKitError> {
        Ok(self
            .runtime
            .cache_public_event_preview(&account_ref, &reference, candidates)
            .await?
            .into())
    }

    /// Bounded native relay refresh, then the resulting local state. Failed or
    /// empty refreshes keep prior content.
    pub async fn resolve_public_event_preview(
        &self,
        account_ref: String,
        reference: String,
    ) -> Result<PublicEventCacheReadFfi, MarmotKitError> {
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
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};

    use super::*;

    fn assert_invariant(read: &PublicEventCacheReadFfi) {
        assert_eq!(
            read.preview.is_some(),
            read.state == PublicEventCacheStateFfi::Present
        );
        assert_eq!(
            read.deletion.is_some(),
            read.state == PublicEventCacheStateFfi::AuthoritativeDeleted
        );
        if let Some(preview) = &read.preview {
            assert_eq!(
                preview.projection_version,
                marmot_app::PUBLIC_EVENT_PROJECTION_VERSION
            );
        }
        if let Some(deletion) = &read.deletion {
            assert_eq!(
                deletion.projection_version,
                marmot_app::PUBLIC_EVENT_PROJECTION_VERSION
            );
        }
        match read.key.key_type {
            PublicEventCacheKeyTypeFfi::EventId => {
                assert!(read.key.event_id_hex.is_some() && read.key.kind.is_none());
            }
            PublicEventCacheKeyTypeFfi::Coordinate => {
                assert!(read.key.event_id_hex.is_none() && read.key.kind.is_some());
            }
        }
    }

    #[tokio::test]
    async fn cached_public_event_previews_round_trip_to_ffi() {
        let root = tempfile::tempdir().unwrap();
        AccountHome::open(root.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(root.path(), "wss://relay.example");
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let keys = Keys::generate();
        let at = Timestamp::now().as_secs() - 100;
        let note = EventBuilder::new(Kind::TextNote, "hello")
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(&keys)
            .unwrap();
        let gone = EventBuilder::new(Kind::TextNote, "gone")
            .custom_created_at(Timestamp::from_secs(at))
            .finalize(&keys)
            .unwrap();
        let deletion = EventBuilder::new(Kind::from(5), "")
            .custom_created_at(Timestamp::from_secs(at + 1))
            .tags([Tag::parse(["e", gone.id.to_hex().as_str()]).unwrap()])
            .finalize(&keys)
            .unwrap();
        let note_ref = format!("nostr:{}", note.id.to_hex().to_uppercase());
        let gone_ref = gone.id.to_hex();
        let missing_ref = "ef".repeat(32);

        let admitted = kit
            .cache_public_event_preview("alice".into(), note_ref.clone(), vec![note.as_json()])
            .await
            .unwrap();
        assert_eq!(admitted.state, PublicEventCacheStateFfi::Present);
        assert_eq!(
            admitted.key.event_id_hex.as_deref(),
            Some(note.id.to_hex().as_str()),
            "the canonical key is lowercase and prefix-free"
        );
        assert_invariant(&admitted);
        let deleted = kit
            .cache_public_event_preview(
                "alice".into(),
                gone_ref.clone(),
                vec![gone.as_json(), deletion.as_json()],
            )
            .await
            .unwrap();
        assert_eq!(
            deleted.state,
            PublicEventCacheStateFfi::AuthoritativeDeleted
        );
        assert_eq!(
            deleted.deletion.as_ref().unwrap().deletion_event_json,
            deletion.as_json()
        );

        let reads = kit
            .cached_public_event_previews(
                "alice".into(),
                vec![
                    missing_ref.clone(),
                    note_ref.clone(),
                    gone_ref.clone(),
                    note_ref.clone(),
                ],
            )
            .unwrap();
        assert_eq!(
            reads.iter().map(|read| read.state).collect::<Vec<_>>(),
            [
                PublicEventCacheStateFfi::Missing,
                PublicEventCacheStateFfi::Present,
                PublicEventCacheStateFfi::AuthoritativeDeleted,
                PublicEventCacheStateFfi::Present,
            ]
        );
        assert_eq!(
            reads[0].key.event_id_hex.as_deref(),
            Some(missing_ref.as_str())
        );
        assert_eq!(reads[1].key, reads[3].key, "duplicates keep their position");
        for duplicate in [&reads[1], &reads[3]] {
            assert_eq!(
                duplicate.preview.as_ref().unwrap().event_json,
                note.as_json()
            );
        }
        reads.iter().for_each(assert_invariant);

        assert!(
            kit.cached_public_event_previews("alice".into(), vec![missing_ref.clone(); 17])
                .is_err(),
            "more than 16 references is rejected"
        );
        assert!(
            kit.cached_public_event_previews(
                "alice".into(),
                vec![missing_ref.clone(), "x".repeat(5001)]
            )
            .is_err(),
            "one invalid reference rejects the whole batch"
        );
        assert!(
            kit.cached_public_event_previews("alice".into(), Vec::new())
                .unwrap()
                .is_empty()
        );
        kit.runtime.shutdown_and_close().await.unwrap();
    }

    #[test]
    fn coordinate_keys_and_busy_rows_convert_with_exclusive_payloads() {
        let author = "ab".repeat(32);
        let read: PublicEventCacheReadFfi = marmot_app::PublicEventCacheRead {
            key: marmot_app::PublicEventCacheKey::Coordinate {
                kind: 30023,
                author_pubkey_hex: author.clone(),
                identifier: String::new(),
            },
            result: marmot_app::PublicEventCacheResult::Busy,
        }
        .into();
        assert_eq!(read.state, PublicEventCacheStateFfi::Busy);
        assert_eq!(read.key.key_type, PublicEventCacheKeyTypeFfi::Coordinate);
        assert_eq!(read.key.author_pubkey_hex, Some(author));
        assert_eq!(read.key.identifier.as_deref(), Some(""));
        assert_invariant(&read);
    }
}
