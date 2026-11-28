use super::*;
use crate::local_submissions::{LocalDraftAdmission, LocalMessageRequest, LocalTypedSend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};

use crate::media::file_transfer::{MAX_FILE_MEDIA_CIPHERTEXT_BYTES, MEDIA_AEAD_TAG_BYTES};

type MediaSubmissionKey = (String, String, String);

#[derive(Default)]
pub(super) struct MediaSubmissionGates {
    gates: HashMap<MediaSubmissionKey, Weak<Mutex<()>>>,
}

impl MediaSubmissionGates {
    fn gate(&mut self, account: &str, group: &str, token: &str) -> Arc<Mutex<()>> {
        let key = (account.to_owned(), group.to_owned(), token.to_owned());
        self.gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = self.gates.get(&key).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        self.gates.insert(key, Arc::downgrade(&gate));
        gate
    }
}

#[derive(Serialize, Deserialize)]
struct MediaUploadReceipt {
    fingerprint: [u8; 32],
    attachments: Vec<crate::media::MediaUploadAttachmentResult>,
}

enum MediaSendSources {
    Bytes(MediaUploadRequest),
    Files(
        crate::MediaFileUploadRequest,
        Arc<crate::MediaFileTransferControl>,
    ),
}

impl MediaSendSources {
    fn control(&self) -> Option<Arc<crate::MediaFileTransferControl>> {
        match self {
            Self::Bytes(_) => None,
            Self::Files(_, control) => Some(control.clone()),
        }
    }

    fn fingerprint(&self, submission: &LocalMessageRequest) -> Result<Sha256, AppError> {
        macro_rules! descriptor {
            ($attachment:ident) => {
                (
                    $attachment.file_name.as_str(),
                    $attachment.media_type.as_str(),
                    $attachment.dim.as_deref(),
                    $attachment.thumbhash.as_deref(),
                )
            };
        }
        let (server, descriptors) = match self {
            Self::Bytes(request) => {
                crate::media::validate_media_upload_batch(&request.attachments)?;
                (
                    &request.blossom_server,
                    request
                        .attachments
                        .iter()
                        .map(|a| descriptor!(a))
                        .collect::<Vec<_>>(),
                )
            }
            Self::Files(request, _) => {
                request.validate()?;
                (
                    &request.blossom_server,
                    request.attachments.iter().map(|a| descriptor!(a)).collect(),
                )
            }
        };
        let input = serde_json::to_vec(&(
            submission.content.as_str(),
            submission.reply_to.as_deref(),
            &submission.tags,
            server,
            descriptors,
        ))
        .map_err(|_| AppError::InvalidAppMessagePayload("invalid media submission".into()))?;
        let mut fingerprint = Sha256::new();
        fingerprint.update(b"mdk-local-media-upload-v1");
        fingerprint.update(input);
        Ok(fingerprint)
    }

    fn replay_fingerprint(self, mut fingerprint: Sha256) -> Result<[u8; 32], AppError> {
        match self {
            Self::Bytes(request) => {
                for attachment in request.attachments {
                    fingerprint.update(hex::encode(Sha256::digest(&attachment.plaintext)));
                }
            }
            Self::Files(request, control) => {
                let mut total = 0u64;
                for attachment in request.attachments {
                    let source = crate::media::outgoing::HostSource::open(
                        std::path::Path::new(&attachment.source_path),
                        attachment.expected_size,
                        control.clone(),
                    )?;
                    total += source.len() + MEDIA_AEAD_TAG_BYTES;
                    if total > MAX_FILE_MEDIA_CIPHERTEXT_BYTES {
                        return Err(AppError::InvalidEncryptedMedia(
                            "file attachments exceed transfer bound".into(),
                        ));
                    }
                    fingerprint.update(source.plaintext_digest()?);
                }
            }
        }
        Ok(fingerprint.finalize().into())
    }

    fn into_payload(self) -> crate::media::file_transfer::MediaUploadPayload {
        use crate::media::file_transfer::{FileUploadSources, MediaUploadPayload};
        match self {
            Self::Bytes(request) => MediaUploadPayload::Bytes(request),
            Self::Files(request, control) => {
                MediaUploadPayload::Files(FileUploadSources::Host(request), control)
            }
        }
    }
}

fn media_token_conflict() -> AppError {
    AppError::InvalidAppMessagePayload("client token is already bound to another submission".into())
}

/// Reject a malformed token before any upload work, not after the PUT.
fn validate_client_token(client_token: &str) -> Result<(), AppError> {
    if client_token.is_empty() || client_token.len() > 128 {
        return Err(AppError::InvalidAppMessagePayload(
            "client token must contain 1 to 128 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

/// A send's member list: account pubkeys, stored lowercase, sorted and once
/// each, so the same accounts make the same request.
fn member_accounts(members: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut accounts = members
        .iter()
        .map(|member| {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(member, &mut bytes).map_err(|_| {
                AppError::InvalidAppMessagePayload(
                    "member accounts must be exactly 32 bytes of hexadecimal".into(),
                )
            })?;
            Ok(hex::encode(bytes))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    accounts.sort();
    accounts.dedup();
    if accounts.is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "member list must name at least one account".into(),
        ));
    }
    Ok(accounts)
}

fn validate_media_reply_target(target: &str) -> Result<(), AppError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(target, &mut bytes).map_err(|_| {
        AppError::InvalidAppMessagePayload(
            "media reply target must be exactly 32 bytes of hexadecimal".into(),
        )
    })
}

fn capture_media_reply(tags: &[Vec<String>]) -> Result<Option<String>, AppError> {
    let mut target: Option<&str> = None;
    for tag in tags {
        if !matches!(tag.first().map(String::as_str), Some("e" | "q")) {
            continue;
        }
        let candidate = tag.get(1).ok_or_else(|| {
            AppError::InvalidAppMessagePayload("media reply reference is missing its target".into())
        })?;
        validate_media_reply_target(candidate)?;
        if target.is_some_and(|target| !target.eq_ignore_ascii_case(candidate)) {
            return Err(AppError::InvalidAppMessagePayload(
                "media reply references have conflicting targets".into(),
            ));
        }
        target = Some(candidate);
    }
    Ok(target.map(|target| {
        let mut target = target.to_owned();
        target.make_ascii_lowercase();
        target
    }))
}

fn capture_media_submission(
    send: bool,
    caption: &Option<String>,
    tags: &mut Vec<Vec<String>>,
) -> Result<Option<LocalMessageRequest>, AppError> {
    if !send {
        return Ok(None);
    }
    crate::messages::validate_message_tags(tags)?;
    let reply_to = capture_media_reply(tags)?;
    let mut tags = std::mem::take(tags);
    tags.retain(|tag| !matches!(tag.first().map(String::as_str), Some("e" | "q")));
    Ok(Some(LocalMessageRequest {
        content: caption.clone().unwrap_or_default(),
        reply_to,
        tags,
        ..Default::default()
    }))
}

impl MarmotAppRuntime {
    /// Upload first, then durably admit the resulting message when `send` is set.
    /// Cancellation does not abandon an upload already handed to this task.
    pub async fn upload_media_with_client_token(
        &self,
        account: &str,
        group: &GroupId,
        mut request: MediaUploadRequest,
        client_token: String,
    ) -> Result<(MediaUploadResult, Option<crate::LocalSendAcceptance>), AppError> {
        validate_client_token(&client_token)?;
        let submission =
            capture_media_submission(request.send, &request.caption, &mut request.message_tags)?;
        request.send = false;
        self.upload_with_client_token(
            account,
            group,
            MediaSendSources::Bytes(request),
            submission,
            client_token,
        )
        .await
    }

    /// File-backed twin of [`Self::upload_media_with_client_token`]. Snapshots
    /// and ciphertext are prepared from `source_path` before any PUT; nothing
    /// is admitted until every upload completed. Cancellation observed before
    /// admission starts prevents publication and releases optional staging;
    /// once admission starts it is not interruptible, and the existing durable
    /// queue then owns delivery (including uncertain-delivery recovery).
    pub async fn upload_media_files_with_client_token(
        &self,
        account: &str,
        group: &GroupId,
        mut request: crate::MediaFileUploadRequest,
        control: Arc<crate::MediaFileTransferControl>,
        client_token: String,
    ) -> Result<(MediaUploadResult, Option<crate::LocalSendAcceptance>), AppError> {
        validate_client_token(&client_token)?;
        control.check()?;
        let submission =
            capture_media_submission(request.send, &request.caption, &mut request.message_tags)?;
        request.send = false;
        self.upload_with_client_token(
            account,
            group,
            MediaSendSources::Files(request, control),
            submission,
            client_token,
        )
        .await
    }

    async fn upload_with_client_token(
        &self,
        account: &str,
        group: &GroupId,
        sources: MediaSendSources,
        submission: Option<LocalMessageRequest>,
        client_token: String,
    ) -> Result<(MediaUploadResult, Option<crate::LocalSendAcceptance>), AppError> {
        let runtime = self.clone();
        let account = account.to_owned();
        let group = group.clone();
        tokio::spawn(async move {
            let owner = runtime.accounts.resolve(&account)?;
            let Some(submission) = submission else {
                let upload = runtime
                    .accounts
                    .upload_media_payload(owner, &group, sources.into_payload())
                    .await?;
                return Ok((upload, None));
            };
            let control = sources.control();
            let group_hex = hex::encode(group.as_slice());
            let gate = runtime
                .accounts
                .shared
                .media_submission_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .gate(&owner.account_id_hex, &group_hex, &client_token);
            let _guard = if let Some(control) = &control {
                tokio::select! {
                    _ = control.cancelled() => return Err(AppError::InvalidEncryptedMedia(
                        "media transfer cancelled".into(),
                    )),
                    guard = gate.lock() => guard,
                }
            } else {
                gate.lock().await
            };
            runtime.accounts.shared.lifecycle().ensure_running()?;
            if let Some(control) = &control {
                control.check()?;
            }
            let owner = runtime.accounts.resolve_original(&owner)?;
            runtime
                .accounts
                .setup_records()
                .require_onboarding_complete_for(&owner)?;
            if !owner.can_sign() {
                return Err(AccountHomeError::SecretNotFound(owner.account_id_hex).into());
            }
            let fingerprint = sources.fingerprint(&submission)?;
            let existing = runtime
                .media_submission(&owner, &group_hex, &client_token)
                .await?;
            if let Some(existing) = existing {
                let receipt = existing
                    .media_upload_receipt_json
                    .as_deref()
                    .ok_or_else(media_token_conflict)?;
                let receipt: MediaUploadReceipt = serde_json::from_str(receipt).map_err(|_| {
                    AppError::InvalidAppMessagePayload("invalid media upload receipt".into())
                })?;
                let shared = &runtime.accounts.shared;
                let mut stopping = shared.lifecycle().subscribe_shutdown();
                let permit = tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut stopping) => return Err(AppError::RuntimeStopping),
                    _ = async {
                        if let Some(control) = &control {
                            control.cancelled().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => return Err(AppError::InvalidEncryptedMedia("media transfer cancelled".into())),
                    permit = shared.media_replay_slots.clone().acquire_owned() => {
                        permit.map_err(|_| AppError::TransportClosed)?
                    }
                };
                let fingerprint = blocking_app_task(move || {
                    let _permit = permit;
                    sources.replay_fingerprint(fingerprint)
                })
                .await?;
                if fingerprint != receipt.fingerprint {
                    return Err(media_token_conflict());
                }
                let refreshed = runtime
                    .media_submission(&owner, &group_hex, &client_token)
                    .await?
                    .filter(|row| {
                        row.message_id_hex == existing.message_id_hex
                            && row.media_upload_receipt_json == existing.media_upload_receipt_json
                    })
                    .ok_or_else(media_token_conflict)?;
                if refreshed.state == 3 {
                    return Err(AppError::InvalidAppMessagePayload(
                        "client token belongs to a rejected submission; use a new token".into(),
                    ));
                }
                return Ok((
                    MediaUploadResult {
                        attachments: receipt.attachments,
                        sent: None,
                    },
                    Some(crate::LocalSendAcceptance {
                        client_token,
                        message_id_hex: refreshed.message_id_hex,
                    }),
                ));
            }

            let upload = runtime
                .accounts
                .upload_media_payload(owner.clone(), &group, sources.into_payload())
                .await?;
            let mut fingerprint = fingerprint;
            for attachment in &upload.attachments {
                fingerprint.update(&attachment.reference.plaintext_sha256);
            }
            runtime
                .admit_uploaded_media(
                    owner,
                    &group,
                    upload,
                    submission,
                    fingerprint.finalize().into(),
                    client_token,
                    control,
                )
                .await
        })
        .await
        .map_err(|_| AppError::TransportClosed)?
    }

    async fn media_submission(
        &self,
        owner: &AccountSummary,
        group_hex: &str,
        token: &str,
    ) -> Result<Option<storage_sqlite::LocalSubmission>, AppError> {
        let (group_hex, token) = (group_hex.to_owned(), token.to_owned());
        let accounts = self.accounts.clone();
        let owner = owner.clone();
        accounts.shared.lifecycle().ensure_running()?;
        let gate = accounts.shared.local_submission_gate(&owner.account_id_hex);
        let mut stopping = accounts.shared.lifecycle().subscribe_shutdown();
        let admission = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(AppError::RuntimeStopping),
            admission = gate.lock_owned() => admission,
        };
        blocking_app_task(move || {
            let _admission = admission;
            accounts.shared.lifecycle().ensure_running()?;
            let account = accounts.resolve_original(&owner)?;
            let submission = accounts
                .app
                .account_storage(&account.label)?
                .app_storage()
                .local_submission(&group_hex, &token)?;
            if accounts.resolve_original(&owner)?.signed_out {
                return Err(AppError::RelayDirectory("account is signed out".into()));
            }
            Ok(submission)
        })
        .await
    }

    /// Durable token admission after a completed upload. Shared validation in
    /// admission rejects a reference whose source epoch is no longer current.
    /// Any failure before acceptance releases the exact bound staging.
    #[allow(clippy::too_many_arguments)]
    async fn admit_uploaded_media(
        &self,
        owner: AccountSummary,
        group: &GroupId,
        upload: MediaUploadResult,
        mut request: LocalMessageRequest,
        fingerprint: [u8; 32],
        client_token: String,
        control: Option<Arc<crate::MediaFileTransferControl>>,
    ) -> Result<(MediaUploadResult, Option<crate::LocalSendAcceptance>), AppError> {
        request.attachments = upload
            .attachments
            .iter()
            .map(|attachment| attachment.reference.clone())
            .collect();
        let receipt = MediaUploadReceipt {
            fingerprint,
            attachments: upload.attachments.clone(),
        };
        let submission = async {
            if let Some(control) = &control {
                control.check()?;
            }
            request.media_upload_receipt_json =
                Some(serde_json::to_string(&receipt).map_err(|_| {
                    AppError::InvalidAppMessagePayload("invalid media upload receipt".into())
                })?);
            self.accounts.shared.lifecycle().ensure_running()?;
            let account = self.accounts.resolve_original(&owner)?;
            self.accounts
                .setup_records()
                .require_onboarding_complete_for(&account)?;
            self.accounts.worker_commands_for_account(account).await?;
            self.submit_local_message_for_account(
                owner.clone(),
                group,
                client_token,
                request,
                None,
                None,
            )
            .await
        }
        .await;
        match submission {
            Ok(accepted) => Ok((upload, Some(accepted))),
            Err(error) => {
                let group_hex = hex::encode(group.as_slice());
                let accounts = self.accounts.clone();
                let admission = accounts
                    .shared
                    .local_submission_gate(&owner.account_id_hex)
                    .lock_owned()
                    .await;
                let cleanup = blocking_app_task(move || {
                    let _admission = admission;
                    let account = accounts.resolve_original(&owner)?;
                    let storage = if accounts.shared.lifecycle().is_stopping() {
                        accounts
                            .app
                            .open_account_storage(&account.label)
                            .ok_or(AppError::RuntimeStopping)?
                    } else {
                        accounts.app.account_storage(&account.label)?
                    };
                    let slots = upload
                        .attachments
                        .iter()
                        .map(|attachment| {
                            serde_json::to_value(attachment.reference.imeta_tag()).map_err(|_| {
                                AppError::InvalidEncryptedMedia("invalid upload descriptor".into())
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    storage
                        .app_storage()
                        .abandon_bound_attachment_uploads(&group_hex, &slots)?;
                    Ok(())
                })
                .await;
                Err(crate::client::preserve_encrypted_media_upload_error(
                    error, cleanup,
                ))
            }
        }
    }

    pub fn local_send_status(
        &self,
        account: &str,
        group: &GroupId,
        token: &str,
    ) -> Result<Option<crate::LocalSendStatus>, AppError> {
        self.accounts.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account)?;
        let submission = self
            .accounts
            .app
            .account_storage(&account.label)?
            .app_storage()
            .local_submission(&hex::encode(group.as_slice()), token)?;
        submission
            .map(|s| {
                Ok(if s.state == 4 {
                    crate::LocalSendStatus::RefusedNewMembers
                } else if let Some(json) = s.outcome_json {
                    crate::LocalSendStatus::Completed(
                        crate::local_submissions::decode_local_outcome(&json)?,
                    )
                } else {
                    match s.state {
                        0 => crate::LocalSendStatus::Queued {
                            message_id_hex: s.message_id_hex,
                        },
                        1 => crate::LocalSendStatus::EngineOwned {
                            message_id_hex: s.message_id_hex,
                        },
                        _ => crate::LocalSendStatus::Rejected,
                    }
                })
            })
            .transpose()
    }

    /// Admit uploaded attachments with an optional explicit reply target.
    /// `None` sends a standalone message; `Some` requires a valid message id
    /// and adds the shared builder's `e` and `q` tags alongside attachment tags.
    /// This method never reads, consumes, or changes the composer draft.
    pub async fn submit_media_attachments(
        &self,
        account: &str,
        group: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
        mut reply_to_message_id: Option<String>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        if let Some(target) = reply_to_message_id.as_mut() {
            validate_media_reply_target(target)?;
            target.make_ascii_lowercase();
        }
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: caption.unwrap_or_default(),
                reply_to: reply_to_message_id,
                attachments,
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    /// Admit the captured ordinary-media payload, consuming only its unchanged draft.
    /// A newer or cleared draft never changes the payload or rejects admission.
    /// Retain the original revision and token for live retries. After restart,
    /// recover existing ownership by token before attempting another admission.
    pub async fn submit_prepared_media_snapshot(
        &self,
        account: &str,
        group: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
        client_token: String,
        consuming_draft: Option<crate::MessageDraftRevision>,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: caption.unwrap_or_default(),
                reply_to: None,
                attachments,
                ..Default::default()
            },
            consuming_draft.map(LocalDraftAdmission::ConsumeIfCurrent),
            None,
        )
        .await
    }

    /// Persist local ownership and correlation before returning. Publication is
    /// independent of this future. Reusing a token with the same request returns
    /// the same identity unless its attempt was rejected before engine acceptance.
    /// Rejected attempts require a new token; a changed request is also rejected.
    pub async fn submit_text(
        &self,
        account: &str,
        group: &GroupId,
        text: String,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_tagged_text(account, group, text, Vec::new(), client_token)
            .await
    }

    /// [`Self::submit_text`] for kind-9 text that carries application tags,
    /// under [`Self::send_tagged_text`]'s tag rules (`imeta` is refused). The
    /// tags travel inside the encrypted event and are part of the request: a
    /// token reused with other tags is a changed request and is refused.
    pub async fn submit_tagged_text(
        &self,
        account: &str,
        group: &GroupId,
        text: String,
        tags: Vec<Vec<String>>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: text,
                tags,
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    pub async fn submit_reply(
        &self,
        account: &str,
        group: &GroupId,
        target: String,
        text: String,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_tagged_reply(account, group, target, text, Vec::new(), client_token)
            .await
    }

    /// [`Self::submit_reply`] with application tags, as
    /// [`Self::submit_tagged_text`]. The reply owns its `e` and `q` tags, so
    /// caller tags with those names are refused.
    pub async fn submit_tagged_reply(
        &self,
        account: &str,
        group: &GroupId,
        target: String,
        text: String,
        tags: Vec<Vec<String>>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: text,
                reply_to: Some(target),
                tags,
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    /// Durably admit a NIP-22 thread message using [`Self::send_thread_message`]'s
    /// placement and tag rules. Attachment references must be in display order.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_thread_message(
        &self,
        account: &str,
        group: &GroupId,
        parent_message_id: String,
        text: String,
        attachments: Vec<MediaAttachmentReference>,
        tags: Vec<Vec<String>>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: text,
                attachments,
                tags,
                typed: Some(LocalTypedSend::Thread { parent_message_id }),
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    /// Durably admit a pack sticker with [`Self::send_tagged_sticker`]'s
    /// authorization and tag rules.
    pub async fn submit_tagged_sticker(
        &self,
        account: &str,
        group: &GroupId,
        sticker_ref: crate::AppStickerRef,
        tags: Vec<Vec<String>>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                tags,
                typed: Some(LocalTypedSend::Sticker(sticker_ref)),
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    /// Durably admit an app-defined event under [`Self::send_custom_event`]'s
    /// rules (MDK-owned kinds are refused), with the same token correlation,
    /// retry identity and [`Self::local_send_status`] reporting as
    /// [`Self::submit_text`]. Kind, tags and content are all part of the
    /// request. Like every token submit, an event identical to an existing one
    /// (same kind, tags, content and second) is refused as a collision.
    pub async fn submit_custom_event(
        &self,
        account: &str,
        group: &GroupId,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content,
                tags,
                custom_kind: Some(kind),
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    /// [`Self::submit_custom_event`] for an event only `members` may receive:
    /// account pubkeys in hex, the sending account's included. The engine
    /// checks the group's member accounts when it encrypts the event, so an
    /// event still queued when an unlisted account joins is not sent, and
    /// [`Self::local_send_status`] reports
    /// [`crate::LocalSendStatus::RefusedNewMembers`]. A listed account's
    /// devices, including ones it links later, receive it. The list is part
    /// of the request.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_custom_event_to_members(
        &self,
        account: &str,
        group: &GroupId,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
        members: Vec<String>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content,
                tags,
                custom_kind: Some(kind),
                only_to_members: Some(member_accounts(members)?),
                ..Default::default()
            },
            None,
            None,
        )
        .await
    }

    pub async fn submit_message_draft(
        &self,
        account: &str,
        group: &GroupId,
        revision: crate::MessageDraftRevision,
        attachments: Vec<MediaAttachmentReference>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: String::new(),
                reply_to: None,
                attachments,
                ..Default::default()
            },
            Some(LocalDraftAdmission::Source(revision)),
            None,
        )
        .await
    }

    /// Admit an edit tied to a durable local send. The edit is retained across
    /// restart and the worker publishes it only after the original is engine-owned.
    pub async fn submit_edit_for_local_send(
        &self,
        account: &str,
        group: &GroupId,
        original_client_token: String,
        content: String,
        edit_client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_tagged_edit_for_local_send(
            account,
            group,
            original_client_token,
            content,
            Vec::new(),
            edit_client_token,
        )
        .await
    }

    /// [`Self::submit_edit_for_local_send`] with application tags on the edit
    /// event, as [`Self::submit_tagged_text`]. An edit does not inherit the
    /// original's tags; pass the ones the edit should carry. The edit owns its
    /// `e` tag, so a caller `e` tag is refused.
    pub async fn submit_tagged_edit_for_local_send(
        &self,
        account: &str,
        group: &GroupId,
        original_client_token: String,
        content: String,
        tags: Vec<Vec<String>>,
        edit_client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            edit_client_token,
            LocalMessageRequest {
                content,
                tags,
                ..Default::default()
            },
            None,
            Some(original_client_token),
        )
        .await
    }

    /// [`Self::submit_tagged_edit_for_local_send`] for an edit only `members`
    /// may receive, under [`Self::submit_custom_event_to_members`]'s rules.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_tagged_edit_for_local_send_to_members(
        &self,
        account: &str,
        group: &GroupId,
        original_client_token: String,
        content: String,
        tags: Vec<Vec<String>>,
        members: Vec<String>,
        edit_client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            edit_client_token,
            LocalMessageRequest {
                content,
                tags,
                only_to_members: Some(member_accounts(members)?),
                ..Default::default()
            },
            None,
            Some(original_client_token),
        )
        .await
    }

    async fn submit_local_message(
        &self,
        account: &str,
        group: &GroupId,
        token: String,
        request: LocalMessageRequest,
        draft: Option<LocalDraftAdmission>,
        edit_of_client_token: Option<String>,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.accounts.worker_commands(account).await?;
        let account = self.accounts.resolve(account)?;
        self.submit_local_message_for_account(
            account,
            group,
            token,
            request,
            draft,
            edit_of_client_token,
        )
        .await
    }

    async fn submit_local_message_for_account(
        &self,
        account: AccountSummary,
        group: &GroupId,
        token: String,
        request: LocalMessageRequest,
        draft: Option<LocalDraftAdmission>,
        edit_of_client_token: Option<String>,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        let accounts = self.accounts.clone();
        let app = self.accounts.app.clone();
        let shared = self.accounts.shared.clone();
        let events = self.accounts.events.clone();
        let group = group.clone();
        // The task outlives cancellation of the host's wait. Wakeup and
        // projection publication belong inside the same owned task.
        blocking_app_task(move || {
            // This blocking task owns only its account's admission gate. The
            // worker cannot select a commit before timing registration; other
            // accounts never wait for this database. Global map locks stay short.
            let gate = shared.local_submission_gate(&account.account_id_hex);
            let admission = gate.blocking_lock();
            shared.lifecycle().ensure_running()?;
            accounts.resolve_original(&account)?;
            let (accepted, update) = app.admit_local_message_with_draft_policy_at(
                &account.label,
                &group,
                token,
                request,
                draft,
                edit_of_client_token,
                crate::unix_now_seconds(),
            )?;
            if update.is_some() {
                let mut queue = shared
                    .local_submission_queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // Shutdown sets stopping before clearing under this same map
                // lock. Recheck here so no admission can register after clear.
                if !shared.lifecycle().is_stopping() {
                    queue.admitted(
                        &account.account_id_hex,
                        &hex::encode(group.as_slice()),
                        &accepted.message_id_hex,
                        shared.observer.performance(),
                    );
                }
            }
            drop(admission);
            if let Some(update) = update {
                account_worker::publish_app_runtime_projection_update(
                    account_worker::Emit::Unpublished(account_worker::Unpublished::OffWorker),
                    &events,
                    &account.account_id_hex,
                    &account.label,
                    update,
                );
            }
            shared.local_submission_wakeups.send_replace(());
            Ok(accepted)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::outgoing::{OutgoingUploads, SendStaging, stage_body};

    #[test]
    fn receipt_lookup_waits_for_admission_without_occupying_the_blocking_pool() {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        executor.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let owner = AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let runtime =
                MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
            let gate = runtime
                .accounts
                .shared
                .local_submission_gate(&owner.account_id_hex);
            let admission = gate.lock_owned().await;
            let (receipt, witness) = tokio::join!(
                biased;
                runtime.media_submission(&owner, "aa", "token"),
                async move {
                    let witness = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        blocking_app_task(|| Ok(())),
                    ).await;
                    drop(admission);
                    witness
                },
            );
            witness
                .expect("a receipt waiter must leave the blocking thread free")
                .unwrap();
            assert!(receipt.unwrap().is_none());
        });
    }

    #[tokio::test]
    async fn stopped_runtime_releases_a_completed_upload_before_admission() {
        let dir = tempfile::tempdir().unwrap();
        let owner = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client
            .create_group("upload cleanup", &[])
            .await
            .unwrap()
            .operation
            .unwrap();
        drop(client);

        let bytes = b"completed upload";
        let (reference, _) = crate::media::tests::attachment_worker_fixture(bytes);
        let upload = MediaUploadResult {
            attachments: vec![crate::media::MediaUploadAttachmentResult {
                reference,
                encrypted_size_bytes: bytes.len() as u64 + MEDIA_AEAD_TAG_BYTES,
            }],
            sent: None,
        };
        let staging = SendStaging::open(&app, "alice", &group, 3).unwrap();
        let mut uploads = OutgoingUploads::new(app.clone(), "alice".into());
        staging
            .stage(uploads.tokens_mut(), bytes.len() as u64, |media, target| {
                stage_body(media, target, &mut &bytes[..], bytes.len() as u64, &|| {
                    false
                })
            })
            .unwrap();
        staging.bind(uploads.tokens(), &upload).unwrap();
        let tokens = uploads.into_tokens();
        let storage = app.open_account_storage("alice").unwrap().app_storage();
        assert!(
            storage
                .attachment_upload_file(&tokens[0])
                .unwrap()
                .is_some()
        );

        let runtime = MarmotAppRuntime::new(app);
        runtime.shutdown().await;
        assert!(matches!(
            runtime
                .admit_uploaded_media(
                    owner,
                    &group,
                    upload,
                    Default::default(),
                    [0; 32],
                    "token".into(),
                    None
                )
                .await,
            Err(AppError::RuntimeStopping)
        ));
        assert!(
            storage
                .attachment_upload_file(&tokens[0])
                .unwrap()
                .is_none()
        );
        runtime.shutdown_and_close().await.unwrap();
    }
}
