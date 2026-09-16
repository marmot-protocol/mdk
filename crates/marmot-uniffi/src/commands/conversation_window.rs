//! Additive C5 screen and revision-safe draft entry points.
use crate::{
    Marmot, MarmotKitError, conversions::*, subscriptions::ConversationWindowSubscription,
};
use std::sync::Arc;
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Open first unread/latest or an explicit message. No implicit mark-read.
    /// Zero timeout uses 30 seconds; timeout/cancellation abandons the opening.
    /// Mode Message requires a message id; other modes reject one. None rows uses 50.
    pub async fn open_conversation_window(
        &self,
        account_ref: String,
        group_id_hex: String,
        mode: ConversationOpenModeFfi,
        message_id_hex: Option<String>,
        initial_rows: Option<u32>,
        timeout_ms: u32,
    ) -> Result<Arc<ConversationWindowSubscription>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        let target = match (mode, message_id_hex) {
            (ConversationOpenModeFfi::Automatic, None) => {
                marmot_app::ConversationOpenTarget::Automatic
            }
            (ConversationOpenModeFfi::Latest, None) => marmot_app::ConversationOpenTarget::Latest,
            (ConversationOpenModeFfi::Message, Some(id)) => {
                marmot_app::ConversationOpenTarget::Message(
                    crate::optional_message_id_hex(Some(id))?
                        .ok_or(MarmotKitError::ConversationWindowInvalidTarget)?,
                )
            }
            _ => return Err(MarmotKitError::ConversationWindowInvalidTarget),
        };
        crate::subscriptions::conversation_window::conversation_deadline(timeout_ms, async {
            let inner = self
                .runtime
                .open_conversation_window(
                    &account_ref,
                    &group,
                    marmot_app::ConversationOpenQuery {
                        target,
                        limit: initial_rows.unwrap_or(50) as usize,
                    },
                )
                .await?;
            Ok(ConversationWindowSubscription::new(inner))
        })
        .await
    }
    /// Submit exactly the selected draft revision. Prepared media must match its descriptors.
    /// Clears only on durable acceptance; do not clear again in the host after delivery.
    pub async fn send_message_draft(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
        attachments: Vec<MediaAttachmentReferenceFfi>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group = group_id_from_hex(revision.inner.group_id_hex())?;
        Ok(self
            .runtime
            .send_message_draft(
                &account_ref,
                &group,
                revision.inner.clone(),
                attachments.into_iter().map(Into::into).collect(),
            )
            .await?
            .into())
    }
    /// Descriptor-only selected draft with an opaque store/group-scoped revision.
    pub fn selected_message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SelectedMessageDraftFfi, MarmotKitError> {
        let group = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .app
            .selected_message_draft(&account_ref, &group)?
            .into())
    }
    pub fn clear_message_draft_if_revision(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
    ) -> Result<SelectedMessageDraftFfi, MarmotKitError> {
        Ok(self
            .app
            .clear_message_draft_if_revision(&account_ref, &revision.inner)?
            .into())
    }
    pub fn save_message_draft_if_revision(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
        content: String,
        reply_to_message_id_hex: Option<String>,
        media_attachments: Vec<MessageDraftAttachmentFfi>,
    ) -> Result<SelectedMessageDraftFfi, MarmotKitError> {
        let reply = crate::optional_message_id_hex(reply_to_message_id_hex)?;
        Ok(self
            .app
            .save_message_draft_if_revision(
                &account_ref,
                &revision.inner,
                &content,
                reply.as_deref(),
                media_attachments.into_iter().map(Into::into).collect(),
            )?
            .into())
    }
    /// Read only the requested local attachment, rejecting a changed selected draft.
    pub fn message_draft_attachment_if_revision(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
        attachment_id: String,
    ) -> Result<Option<Vec<u8>>, MarmotKitError> {
        Ok(self.app.message_draft_attachment_if_revision(
            &account_ref,
            &revision.inner,
            &attachment_id,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;
    use std::time::Duration;
    #[tokio::test]
    async fn conversation_native_window_round_trip_commands_drafts_and_close() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let endpoint = TransportEndpoint(url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .account
            .account_id_hex;
        let group = kit
            .create_group(account.clone(), "native window".into(), vec![], None)
            .await
            .unwrap();
        assert_eq!(hex::decode(&group).unwrap().len(), 16);
        for i in 0..6 {
            kit.send_text(
                account.clone(),
                group.clone(),
                format!("native message {i}"),
            )
            .await
            .unwrap();
        }
        let selected = kit
            .selected_message_draft(account.clone(), group.clone())
            .unwrap();
        let selected = kit
            .save_message_draft_if_revision(
                account.clone(),
                selected.revision,
                "unsent".into(),
                None,
                vec![MessageDraftAttachmentFfi {
                    id: "local-media".into(),
                    file_name: "voice.ogg".into(),
                    media_type: "audio/ogg".into(),
                    plaintext: vec![1, 2, 3],
                    dim: None,
                    thumbhash: None,
                    duration_seconds: Some(1.5),
                    waveform_samples: vec![0.25, 0.5],
                }],
            )
            .unwrap();
        let window = kit
            .open_conversation_window(
                account.clone(),
                group.clone(),
                ConversationOpenModeFfi::Latest,
                None,
                Some(2),
                0,
            )
            .await
            .unwrap();
        let mut initial = window.snapshot().unwrap();
        assert!(window.snapshot().is_none());
        assert_eq!(initial.messages.len(), 2);
        assert_eq!(
            initial.draft.draft.as_ref().unwrap().media_attachments[0].plaintext_size,
            3
        );
        assert_eq!(
            initial.draft.draft.as_ref().unwrap().media_attachments[0].waveform_samples,
            vec![0.25, 0.5]
        );
        assert!(matches!(
            initial.anchor.kind,
            ConversationAnchorKindFfi::Latest
        ));
        let author = initial.messages[0].references.sender.as_ref().unwrap();
        assert!(
            initial
                .identities
                .iter()
                .any(|i| &i.account_id_hex == author)
        );
        assert!(initial.messages[0].timeline.tags.is_empty());
        assert_eq!(
            kit.message_draft_attachment_if_revision(
                account.clone(),
                initial.draft.revision.clone(),
                "local-media".into()
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(initial.header.epoch.is_none());
        assert!(!initial.header.capabilities.can_send);
        // Commands below test a quiet live window. Consume the independent
        // authority replacement first, so their revision cannot race it.
        initial = tokio::time::timeout(std::time::Duration::from_secs(10), window.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(initial.header.epoch.is_some());
        assert!(initial.header.capabilities.can_send);
        let mut wrong = initial.revision.clone();
        wrong.generation.push('x');
        assert!(matches!(
            window.return_to_latest(wrong, 0).await,
            Err(MarmotKitError::ConversationWindowWrongGeneration)
        ));
        let missing = "00".repeat(32);
        assert!(matches!(
            kit.open_conversation_window(
                account.clone(),
                group.clone(),
                ConversationOpenModeFfi::Message,
                Some(missing.clone()),
                Some(2),
                0
            )
            .await,
            Err(MarmotKitError::ConversationWindowMessageNotRetained)
        ));
        assert!(matches!(
            window
                .jump_to_message(initial.revision.clone(), missing, 0)
                .await,
            Err(MarmotKitError::ConversationWindowMessageNotRetained)
        ));
        // Missing jumps retain the old revision and leave paging and the stream usable.
        let (received, paged) = tokio::join!(
            window.next(),
            window.page(
                initial.revision.clone(),
                ConversationPageDirectionFfi::Older,
                2,
                0
            )
        );
        let paged = paged.unwrap();
        assert_eq!(
            received.unwrap().unwrap().revision.sequence,
            paged.revision.sequence
        );
        assert_eq!(paged.messages.len(), 4);
        assert!(matches!(
            window.return_to_latest(initial.revision, 0).await,
            Err(MarmotKitError::ConversationWindowStale)
        ));
        let target = paged.messages[0].timeline.message_id_hex.clone();
        let (received, anchored) = tokio::join!(
            window.next(),
            window.set_visible_anchor(paged.revision.clone(), target.clone(), 0),
        );
        let anchored = anchored.unwrap();
        assert_eq!(
            received.unwrap().unwrap().revision.sequence,
            anchored.revision.sequence
        );
        assert!(matches!(
            anchored.anchor.kind,
            ConversationAnchorKindFfi::Retained
        ));
        let (received, jumped) = tokio::join!(
            window.next(),
            window.jump_to_message(anchored.revision, target.clone(), 0),
        );
        let jumped = jumped.unwrap();
        assert_eq!(
            received.unwrap().unwrap().revision.sequence,
            jumped.revision.sequence
        );
        assert_eq!(
            jumped.messages[jumped.anchor.index.unwrap() as usize]
                .timeline
                .message_id_hex,
            target
        );
        // Cancellation of next must not swallow a subsequent draft replacement.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), window.next())
                .await
                .is_err()
        );
        let fresh = kit
            .save_message_draft_if_revision(
                account.clone(),
                selected.revision,
                "new edit".into(),
                None,
                vec![],
            )
            .unwrap();
        assert!(matches!(
            kit.clear_message_draft_if_revision(account.clone(), initial.draft.revision.clone()),
            Err(MarmotKitError::MessageDraftRevisionConflict)
        ));
        assert!(
            kit.message_draft_attachment_if_revision(
                account.clone(),
                initial.draft.revision,
                "local-media".into()
            )
            .is_err()
        );
        let update = tokio::time::timeout(Duration::from_secs(5), window.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(update.draft.draft.unwrap().content, "new edit");
        kit.send_message_draft(account.clone(), fresh.revision, vec![])
            .await
            .unwrap();
        assert!(
            kit.selected_message_draft(account.clone(), group.clone())
                .unwrap()
                .draft
                .is_none()
        );
        let _ = window.next().await.unwrap();
        let next = window.next();
        let close = window.cancel();
        let (closed, ()) = tokio::join!(next, close);
        assert!(closed.unwrap().is_none());
        window.cancel().await;
        assert!(matches!(
            window.return_to_latest(paged.revision, 0).await,
            Err(MarmotKitError::ConversationWindowClosed)
        ));
        assert!(matches!(
            kit.open_conversation_window(
                account.clone(),
                group.clone(),
                ConversationOpenModeFfi::Message,
                None,
                None,
                0
            )
            .await,
            Err(MarmotKitError::ConversationWindowInvalidTarget)
        ));
        assert!(matches!(
            kit.open_conversation_window(
                account,
                group,
                ConversationOpenModeFfi::Latest,
                None,
                Some(201),
                0
            )
            .await,
            Err(MarmotKitError::ConversationWindowInvalidLimit)
        ));
        kit.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn conversation_native_deadline_bounds_default_and_explicit_waits() {
        use crate::subscriptions::conversation_window::conversation_deadline;
        for millis in [0, 25] {
            let start = tokio::time::Instant::now();
            let result = conversation_deadline::<()>(millis, std::future::pending()).await;
            assert!(matches!(
                result,
                Err(MarmotKitError::ConversationWindowTimedOut)
            ));
            assert_eq!(
                start.elapsed(),
                Duration::from_millis(if millis == 0 { 30_000 } else { millis as u64 })
            );
        }
    }
}
