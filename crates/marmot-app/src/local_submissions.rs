//! Durable device-local admission and exact host correlation. Engine validation
//! and publication remain with the account worker; admission performs no I/O to relays.
use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::storage::{GroupStorage, StorageProvider};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::LocalSubmission;

use crate::messages::{AppMessageIntent, build_inner_event_with_media_reply, encode_inner_event};
use crate::{
    AppError, AppMessageProjection, AppProjectionUpdate, MarmotApp, MediaAttachmentReference,
    MessageDraftRevision, unix_now_seconds,
};

/// Durable local ownership, not a relay acknowledgment or successful MLS send.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalSendAcceptance {
    pub client_token: String,
    pub message_id_hex: String,
}

impl std::fmt::Debug for LocalSendAcceptance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSendAcceptance")
            .finish_non_exhaustive()
    }
}

/// Queryable after restart; transport delivery is also reflected by the ordinary
/// timeline source identity and invalidation updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSendStatus {
    Queued,
    EngineOwned,
    Completed(crate::SendSummary),
    Rejected,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LocalMessageRequest {
    pub content: String,
    pub reply_to: Option<String>,
    pub attachments: Vec<MediaAttachmentReference>,
}

#[derive(Serialize, Deserialize)]
struct RetainedLocalRequest {
    version: u8,
    request: LocalMessageRequest,
}

impl LocalMessageRequest {
    pub(crate) fn decode_retained(json: &str) -> Result<Self, AppError> {
        let retained: RetainedLocalRequest = serde_json::from_str(json).map_err(|_| {
            AppError::InvalidAppMessagePayload("invalid local submission request".into())
        })?;
        if retained.version != 1 {
            return Err(AppError::InvalidAppMessagePayload(
                "unsupported local submission request version".into(),
            ));
        }
        Ok(retained.request)
    }

    fn encode_retained(&self) -> Result<String, AppError> {
        serde_json::to_string(&RetainedLocalRequest {
            version: 1,
            request: self.clone(),
        })
        .map_err(|_| AppError::InvalidAppMessagePayload("invalid local submission request".into()))
    }
    pub(crate) fn intent(&self) -> AppMessageIntent {
        if !self.attachments.is_empty() {
            AppMessageIntent::Media {
                attachments: self.attachments.clone(),
                caption: Some(self.content.clone()),
            }
        } else if let Some(target) = &self.reply_to {
            AppMessageIntent::Reply {
                target_message_id: target.clone(),
                text: self.content.clone(),
            }
        } else {
            AppMessageIntent::Chat {
                content: self.content.clone(),
            }
        }
    }
}

impl MarmotApp {
    pub(crate) fn finish_local_message(
        &self,
        label: &str,
        submission: &LocalSubmission,
        result: &Result<crate::SendSummary, AppError>,
    ) -> Result<Option<AppProjectionUpdate>, AppError> {
        let storage = self.account_storage(label)?;
        let outcome = result
            .as_ref()
            .ok()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| {
                AppError::InvalidAppMessagePayload("invalid local submission outcome".into())
            })?;
        StorageProvider::with_transaction(&storage, |storage| {
            let Some(current) =
                storage.local_submission(&submission.group_id_hex, &submission.client_token)?
            else {
                return Ok(None);
            };
            let update = if result.is_err() && current.state == 0 {
                self.invalidate_timeline_app_event(
                    label,
                    &submission.group_id_hex,
                    &submission.message_id_hex,
                    crate::LOCAL_PUBLISH_FAILED_REASON,
                )?
            } else {
                None
            };
            storage.finish_local_submission(
                &submission.group_id_hex,
                &submission.client_token,
                outcome.as_deref(),
            )?;
            Ok(update)
        })
    }

    pub(crate) fn admit_local_message(
        &self,
        account_ref: &str,
        group: &cgka_traits::GroupId,
        token: String,
        mut request: LocalMessageRequest,
        draft: Option<MessageDraftRevision>,
    ) -> Result<(LocalSendAcceptance, Option<AppProjectionUpdate>), AppError> {
        if token.is_empty() || token.len() > 128 {
            return Err(AppError::InvalidAppMessagePayload(
                "client token must contain 1 to 128 UTF-8 bytes".into(),
            ));
        }
        let account = self.account_home().account(account_ref)?;
        let storage = self.draft_storage(&account.label)?;
        let group_hex = hex::encode(group.as_slice());
        // Bind draft retries to the opaque revision, not to whichever draft is
        // now selected (the accepted draft may already have been consumed).
        let mut request_hash = Sha256::new();
        request_hash.update(b"mdk-local-submission-v1");
        if let Some(revision) = &draft {
            if revision.group_id_hex() != group_hex {
                return Err(AppError::MessageDraftRevisionConflict);
            }
            request_hash.update(revision.local_submission_binding());
        }
        request_hash.update(
            serde_json::to_vec(&request).map_err(|_| {
                AppError::InvalidAppMessagePayload("invalid local submission".into())
            })?,
        );
        let request_hash = request_hash.finalize().to_vec();
        let result = StorageProvider::with_transaction(&storage, |storage| {
            if let Some(existing) = storage.local_submission(&group_hex, &token)? {
                if existing.request_hash != request_hash {
                    return Err(AppError::InvalidAppMessagePayload(
                        "client token is already bound to another submission".into(),
                    ));
                }
                return Ok((
                    LocalSendAcceptance {
                        client_token: token.clone(),
                        message_id_hex: existing.message_id_hex,
                    },
                    None,
                ));
            }
            let stored_group = storage.get_group(group)?;
            if stored_group.is_terminal() {
                return Err(if stored_group.removed {
                    AppError::GroupRemoved(group_hex.clone())
                } else {
                    AppError::GroupDisbanding(group_hex.clone())
                });
            }
            if storage.direct_conversation_has_blocked_user(&group_hex)? {
                return Err(AppError::UserBlocked);
            }
            if let Some(revision) = &draft {
                let selected = storage.selected_message_draft(&group_hex)?;
                if selected.revision != *revision {
                    return Err(AppError::MessageDraftRevisionConflict);
                }
                let selected = selected
                    .draft
                    .ok_or_else(|| AppError::InvalidMessageDraft("draft is empty".into()))?;
                if selected.media_attachments.len() != request.attachments.len()
                    || selected
                        .media_attachments
                        .iter()
                        .zip(&request.attachments)
                        .any(|(a, b)| a.file_name != b.file_name || a.media_type != b.media_type)
                {
                    return Err(AppError::InvalidMessageDraft(
                        "prepared media must match the selected draft".into(),
                    ));
                }
                request.content = selected.content;
                request.reply_to = selected.reply_to_message_id_hex;
            }
            let intent = request.intent();
            let media_reply = (!request.attachments.is_empty())
                .then_some(request.reply_to.as_deref())
                .flatten();
            let mut event = build_inner_event_with_media_reply(
                &intent,
                &account.account_id_hex,
                unix_now_seconds(),
                media_reply,
            )?;
            // Independent entropy, never the host token or a hash of it. Nostr
            // timestamps have second precision; identical rapid sends need
            // distinct event identities without changing displayed content.
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
                AppError::InvalidAppMessagePayload("message identity entropy unavailable".into())
            })?;
            event.tags.push(vec!["nonce".into(), hex::encode(nonce)]);
            event = MarmotInnerEvent::new(
                event.pubkey,
                event.created_at,
                event.kind,
                event.tags,
                event.content,
            );
            let payload = encode_inner_event(&event)?;
            let expected_epoch = request.attachments.first().map(|a| a.source_epoch);
            if request
                .attachments
                .iter()
                .any(|a| Some(a.source_epoch) != expected_epoch)
            {
                return Err(AppError::InvalidEncryptedMedia(
                    "media references must share an epoch".into(),
                ));
            }
            for attachment in &request.attachments {
                attachment.validate(self.allow_loopback_blob_endpoints())?;
                if attachment.source_epoch != stored_group.epoch.0 {
                    return Err(AppError::MediaReferenceStaleEpoch {
                        source_epoch: attachment.source_epoch,
                        current_epoch: stored_group.epoch.0,
                    });
                }
            }
            let submission = LocalSubmission {
                group_id_hex: group_hex.clone(),
                client_token: token.clone(),
                message_id_hex: event.id.clone(),
                request_hash: request_hash.clone(),
                payload_hash: Sha256::digest(&payload).to_vec(),
                payload: Some(payload),
                request_json: Some(request.encode_retained()?),
                expected_epoch,
                state: 0,
                outcome_json: None,
            };
            storage.insert_local_submission(&submission)?;
            let projection = AppMessageProjection {
                authority: None,
                message_id_hex: event.id.clone(),
                source_message_id_hex: None,
                group_id_hex: group_hex.clone(),
                sender: event.pubkey,
                plaintext: event.content,
                kind: event.kind,
                tags: event.tags,
                direction: "sent".into(),
                source_epoch: None,
                retention: None,
                recorded_at: Some(event.created_at),
                origin_commit_id: None,
                moderation_grant: false,
            };
            let update = self.record_account_app_event(&account.label, &projection)?;
            if let Some(revision) = &draft {
                storage
                    .clear_message_draft_if_revision(revision)
                    .map_err(|error| crate::drafts::revision_error(error, &group_hex))?;
            }
            Ok((
                LocalSendAcceptance {
                    client_token: token.clone(),
                    message_id_hex: event.id,
                },
                Some(update),
            ))
        })?;
        if draft.is_some() && result.1.is_some() {
            self.notify_draft_changed(&account.label, &group_hex);
        }
        Ok(result)
    }
}
