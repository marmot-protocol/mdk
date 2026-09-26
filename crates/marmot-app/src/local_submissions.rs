//! Durable device-local admission and exact host correlation. Engine validation
//! and publication remain with the account worker; admission performs no I/O to relays.
mod outcome;
pub(crate) use outcome::decode_local_outcome;
use outcome::encode_local_outcome;

use cgka_traits::app_event::MarmotAppEvent as MarmotInnerEvent;
use cgka_traits::storage::{GroupStorage, StorageProvider};
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

/// Decode for validation/projection, but preserve the bytes that bind engine
/// acceptance to the durable app queue. Re-encoding is not this boundary's job.
pub(crate) fn retained_event(
    submission: &LocalSubmission,
) -> Result<(MarmotInnerEvent, Vec<u8>), AppError> {
    let payload = submission.payload.as_deref().ok_or_else(|| {
        AppError::InvalidAppMessagePayload("missing local submission payload".into())
    })?;
    if Sha256::digest(payload).as_slice() != submission.payload_hash {
        return Err(AppError::InvalidAppMessagePayload(
            "local submission payload digest mismatch".into(),
        ));
    }
    let event = MarmotInnerEvent::decode(payload).map_err(|_| {
        AppError::InvalidAppMessagePayload("invalid local submission payload".into())
    })?;
    Ok((event, payload.to_vec()))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    edit_of_client_token: Option<String>,
}

impl LocalMessageRequest {
    pub(crate) fn decode_retained(json: &str) -> Result<(Self, Option<String>), AppError> {
        let retained: RetainedLocalRequest = serde_json::from_str(json).map_err(|_| {
            AppError::InvalidAppMessagePayload("invalid local submission request".into())
        })?;
        if retained.version != 1 {
            return Err(AppError::InvalidAppMessagePayload(
                "unsupported local submission request version".into(),
            ));
        }
        Ok((retained.request, retained.edit_of_client_token))
    }

    fn encode_retained(&self, edit_of_client_token: Option<&str>) -> Result<String, AppError> {
        serde_json::to_string(&RetainedLocalRequest {
            version: 1,
            request: self.clone(),
            edit_of_client_token: edit_of_client_token.map(str::to_owned),
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
        let outcome = result.as_ref().ok().map(encode_local_outcome).transpose()?;
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
        request: LocalMessageRequest,
        draft: Option<MessageDraftRevision>,
    ) -> Result<(LocalSendAcceptance, Option<AppProjectionUpdate>), AppError> {
        self.admit_local_message_at(
            account_ref,
            group,
            token,
            request,
            draft,
            unix_now_seconds(),
        )
    }

    // Explicit event time makes collision tests independent of wall-clock edges.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_local_message_at(
        &self,
        account_ref: &str,
        group: &cgka_traits::GroupId,
        token: String,
        request: LocalMessageRequest,
        draft: Option<MessageDraftRevision>,
        created_at: u64,
    ) -> Result<(LocalSendAcceptance, Option<AppProjectionUpdate>), AppError> {
        self.admit_local_message_with_edit_at(
            account_ref,
            group,
            token,
            request,
            draft,
            None,
            created_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_local_message_with_edit_at(
        &self,
        account_ref: &str,
        group: &cgka_traits::GroupId,
        token: String,
        mut request: LocalMessageRequest,
        draft: Option<MessageDraftRevision>,
        edit_of_client_token: Option<String>,
        created_at: u64,
    ) -> Result<(LocalSendAcceptance, Option<AppProjectionUpdate>), AppError> {
        if token.is_empty() || token.len() > 128 {
            return Err(AppError::InvalidAppMessagePayload(
                "client token must contain 1 to 128 UTF-8 bytes".into(),
            ));
        }
        if let Some(original) = &edit_of_client_token
            && (original.is_empty() || original.len() > 128 || original == &token)
        {
            return Err(AppError::InvalidAppMessagePayload(
                "invalid original client token for pending edit".into(),
            ));
        }
        let account = self.account_home().account(account_ref)?;
        let storage = self.draft_storage(&account.label)?;
        let group_hex = hex::encode(group.as_slice());
        // Bind draft retries to the opaque revision, not to whichever draft is
        // now selected (the accepted draft may already have been consumed).
        let mut request_hash = Sha256::new();
        request_hash.update(b"mdk-local-submission-v1");
        if let Some(original) = &edit_of_client_token {
            request_hash.update(b"pending-edit-of-token-v1");
            request_hash.update((original.len() as u64).to_le_bytes());
            request_hash.update(original.as_bytes());
        }
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
                if existing.state == 3 {
                    return Err(AppError::InvalidAppMessagePayload(
                        "client token belongs to a rejected submission; use a new token".into(),
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
            let mut event_created_at = created_at;
            let intent = if let Some(original_token) = &edit_of_client_token {
                let original = storage
                    .local_submission(&group_hex, original_token)?
                    .ok_or_else(|| {
                        AppError::InvalidAppMessagePayload(
                            "original local send was not found".into(),
                        )
                    })?;
                if original.state == 3 {
                    return Err(AppError::InvalidAppMessagePayload(
                        "original local send was rejected".into(),
                    ));
                }
                let original_row = storage
                    .timeline_message(&group_hex, &original.message_id_hex)?
                    .ok_or_else(|| {
                        AppError::InvalidAppMessagePayload(
                            "original local message is unavailable".into(),
                        )
                    })?;
                if original_row.kind != 9 || original_row.direction != "sent" {
                    return Err(AppError::InvalidAppMessagePayload(
                        "pending edit requires an outgoing text message".into(),
                    ));
                }
                // Edit resolution uses (second, event id), not queue order.
                // Give rapid local revisions strictly increasing seconds so
                // the last submitted text remains the effective version.
                if let Some(previous) = original_row.edit {
                    event_created_at = event_created_at.max(previous.edited_at.saturating_add(1));
                    if event_created_at > created_at.saturating_add(30) {
                        return Err(AppError::InvalidAppMessagePayload(
                            "pending edit rate limit: retry shortly".into(),
                        ));
                    }
                }
                AppMessageIntent::Edit {
                    target_message_id: original.message_id_hex,
                    content: request.content.clone(),
                }
            } else {
                request.intent()
            };
            let media_reply = (!request.attachments.is_empty())
                .then_some(request.reply_to.as_deref())
                .flatten();
            let event = build_inner_event_with_media_reply(
                &intent,
                &account.account_id_hex,
                event_created_at,
                media_reply,
            )?;
            // Keep the existing wire identity. A new token must not overwrite
            // another admission's correlation or adopt an existing legacy row.
            // Same-token retries returned above, before rebuilding an event.
            if storage.local_message_identity_exists(&group_hex, &event.id)? {
                return Err(AppError::InvalidAppMessagePayload(
                    "message identity collision: an identical event already exists; submission was not accepted".into(),
                ));
            }
            let payload = encode_inner_event(&event)?;
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
                request_json: Some(request.encode_retained(edit_of_client_token.as_deref())?),
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
