//! Final-message sends, agent activity/operation/group-system events, and debug send recording.

use agent_control::{
    AgentControlDebugFinalSend, AgentControlEvent, AgentControlMediaRef, AgentControlMediaUpload,
    AgentControlResponse,
};
use cgka_traits::GroupId;
use marmot_app::{
    AgentOperationEventRequest, MediaAttachmentReference, MediaLocator,
    MediaUploadAttachmentRequest, MediaUploadRequest,
};

use crate::AgentConnector;
use crate::error::ConnectorError;
use crate::validation::normalize_hex;

/// Current schema version for persisted `send_final` request fingerprints.
pub(crate) const SEND_FINAL_FINGERPRINT_VERSION: u8 = 1;

/// Server-derived fingerprint of a `send_final` request: a versioned SHA-256 digest
/// over the destination (account + group), message text, and optional reply target.
/// The digest is stable across Rust/toolchain releases and is safe to persist on
/// disk for connector-restart dedup.
pub(crate) fn send_final_fingerprint(
    account_id_hex: &str,
    group_id_hex: &str,
    text: &str,
    reply_to_message_id_hex: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};

    let preimage = serde_json::json!([
        SEND_FINAL_FINGERPRINT_VERSION,
        account_id_hex,
        group_id_hex,
        text,
        reply_to_message_id_hex,
    ]);
    let bytes = serde_json::to_vec(&preimage).expect("send_final fingerprint preimage cannot fail");
    hex::encode(Sha256::digest(bytes))
}

/// Map a control-plane media reference (the non-secret mirror) back into the
/// app-runtime `MediaAttachmentReference`. Field-for-field; the content key is
/// never part of either type, so this is a pure structural reshape.
/// Reduce a sender-controlled media file name to a safe basename so a download
/// cannot escape its per-blob temp dir (e.g. "../../x" -> "x"). Falls back to
/// "media" for empty or parent-only names.
pub(crate) fn safe_media_filename(name: &str) -> &str {
    std::path::Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("media")
}

pub(crate) fn media_ref_to_reference(media: AgentControlMediaRef) -> MediaAttachmentReference {
    MediaAttachmentReference {
        locators: media
            .locators
            .into_iter()
            .map(|locator| MediaLocator {
                kind: locator.kind,
                value: locator.value,
            })
            .collect(),
        ciphertext_sha256: media.ciphertext_sha256,
        plaintext_sha256: media.plaintext_sha256,
        nonce_hex: media.nonce_hex,
        file_name: media.file_name,
        media_type: media.media_type,
        version: media.version,
        source_epoch: media.source_epoch,
        dim: media.dim,
        thumbhash: media.thumbhash,
    }
}

impl AgentConnector {
    pub(crate) async fn send_final_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        if self.debug_controls {
            return self.debug_record_final_send_response(
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex,
            );
        }

        // Server-derived request fingerprint: a reused idempotency key only short-
        // circuits when the request it identifies is the same one. A reused key
        // carrying a different request body is a cache miss, so dedup can never
        // return ids belonging to an unrelated send.
        let fingerprint = send_final_fingerprint(
            account_id_hex,
            group_id_hex,
            &text,
            reply_to_message_id_hex.as_deref(),
        );

        // Idempotent durable send: if this key already committed a matching send,
        // return the original message ids without re-sending so a retry after a
        // post-write timeout cannot double-post an unrecallable message.
        if let Some(key) = idempotency_key.as_deref()
            && let Some(message_ids_hex) = self.idempotency.get(key, &fingerprint)
        {
            return Ok(AgentControlResponse::FinalSent { message_ids_hex });
        }

        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let summary = if let Some(target_message_id) = reply_to_message_id_hex {
            self.runtime
                .reply_to_message(&account.label, &group_id, &target_message_id, &text)
                .await?
        } else {
            self.runtime
                .send_message(&account.label, &group_id, text.into_bytes())
                .await?
        };
        // Record only after a successful send so a failed send remains retryable.
        // A key already bound to a different fingerprint is left untouched (first
        // write wins), so this send simply proceeds without caching.
        if let Some(key) = idempotency_key {
            self.idempotency
                .record(key, fingerprint, summary.message_ids.clone());
        }
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: summary.message_ids,
        })
    }

    /// Delete (retract) a previously-sent group message by id. Emits a kind-5
    /// deletion event referencing the target; returns its durable message ids.
    pub(crate) async fn delete_message_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        target_message_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let target_message_id = normalize_hex(target_message_id_hex)?;
        let summary = self
            .runtime
            .delete_message(&account.label, &group_id, &target_message_id)
            .await?;
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: summary.message_ids,
        })
    }

    /// Report group membership for an account's group so a channel can decide
    /// activation policy: `is_direct` (exactly two members, i.e. an effective DM
    /// where the agent always replies) vs a multi-party group that gates on
    /// being addressed.
    pub(crate) async fn group_info_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let state = self
            .runtime
            .group_mls_state(&account.label, &group_id)
            .await?;
        let member_count = u32::try_from(state.member_count).unwrap_or(u32::MAX);
        Ok(AgentControlResponse::GroupInfo {
            account_id_hex: account.account_id_hex,
            group_id_hex: hex::encode(group_id.as_slice()),
            member_count,
            is_direct: state.member_count == 2,
            subject: None,
        })
    }

    pub(crate) fn debug_inject_inbound_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        sender_account_id_hex: &str,
        text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let event = AgentControlEvent::InboundMessage {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            message_id_hex: normalize_hex(message_id_hex)?,
            sender_account_id_hex: normalize_hex(sender_account_id_hex)?,
            text,
            mentions_self: false,
            reply_to_message_id_hex: None,
            sender_display_name: None,
            media: Vec::new(),
        };
        let _ = self.debug_events.send(event);
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) fn debug_recorded_finals_response(
        &self,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        Ok(AgentControlResponse::DebugRecordedFinals {
            sends: self.debug_final_sends.list(),
        })
    }

    fn debug_record_final_send_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let record = self.debug_final_sends.record(AgentControlDebugFinalSend {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            text,
            reply_to_message_id_hex: reply_to_message_id_hex
                .map(|value| normalize_hex(&value))
                .transpose()?,
            message_ids_hex: Vec::new(),
        });
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: record.message_ids_hex,
        })
    }

    fn ensure_debug_controls(&self) -> Result<(), ConnectorError> {
        if self.debug_controls {
            Ok(())
        } else {
            Err(ConnectorError::DebugControlsDisabled)
        }
    }

    pub(crate) async fn send_agent_activity_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        status: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let reply_to_message_id_hex = reply_to_message_id_hex
            .map(|value| normalize_hex(&value))
            .transpose()?;
        let summary = self
            .runtime
            .send_agent_activity(
                &account.label,
                &group_id,
                status,
                text,
                reply_to_message_id_hex,
                extra,
            )
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_agent_operation_event_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        event_type: String,
        status: String,
        operation_id: Option<String>,
        run_id: Option<String>,
        turn_id: Option<String>,
        name: Option<String>,
        text: String,
        preview: Option<String>,
        details: Option<serde_json::Value>,
        sequence: Option<u64>,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let reply_to_message_id_hex = reply_to_message_id_hex
            .map(|value| normalize_hex(&value))
            .transpose()?;
        let summary = self
            .runtime
            .send_agent_operation_event(
                &account.label,
                &group_id,
                AgentOperationEventRequest {
                    event_type,
                    status,
                    operation_id,
                    run_id,
                    turn_id,
                    name,
                    text,
                    preview,
                    details,
                    sequence,
                    ok,
                    duration_ms,
                    reply_to_message_id: reply_to_message_id_hex,
                },
            )
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }

    pub(crate) async fn send_group_system_event_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let summary = self
            .runtime
            .send_group_system_event(&account.label, &group_id, system_type, text, data)
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }

    /// Encrypt + upload local files as encrypted media and send them as a kind-9
    /// message. The plaintext bytes are read from the connector host by path and
    /// never crossed the control plane; the content key stays in the runtime.
    ///
    /// Trust boundary: the connector reads `attachment.path` verbatim and is the
    /// generic glue serving every control-plane gateway (OpenClaw, Hermes), so it
    /// cannot know which paths a given deployment considers safe. Confining the
    /// path to an allowlisted media root is therefore the caller's responsibility
    /// — e.g. the OpenClaw channel adapter validates the resolved local path with
    /// `assertLocalMediaAllowed` before issuing `send_media`, mirroring the
    /// inbound model where downloaded media is re-staged under an allowlisted
    /// root. A gateway that forwards an unconstrained, tool-influenced path would
    /// let a prompt-injected agent read an arbitrary connector-host file; that
    /// must be prevented gateway-side, not here.
    pub(crate) async fn send_media_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        attachments: Vec<AgentControlMediaUpload>,
        caption: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let mut upload_attachments = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let plaintext = tokio::fs::read(&attachment.path).await?;
            upload_attachments.push(MediaUploadAttachmentRequest {
                file_name: attachment.file_name,
                media_type: attachment.media_type,
                plaintext,
                dim: attachment.dim,
                thumbhash: attachment.thumbhash,
            });
        }
        let result = self
            .runtime
            .upload_media(
                &account.label,
                &group_id,
                MediaUploadRequest {
                    attachments: upload_attachments,
                    caption,
                    send: true,
                    blossom_server: None,
                },
            )
            .await?;
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: result.sent.map(|sent| sent.message_ids).unwrap_or_default(),
        })
    }

    /// Fetch + decrypt an inbound media reference and write the plaintext to a
    /// per-blob temp dir on the connector host (0600). The content key stays in
    /// the runtime; only the local path + metadata are returned to the agent.
    pub(crate) async fn download_media_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        media: AgentControlMediaRef,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let reference = media_ref_to_reference(media);
        // Derive a unique, stable-per-blob subdir from the ciphertext hash so
        // repeat downloads land in the same place and distinct blobs do not
        // collide. The hash is opaque ciphertext metadata, not an id we log.
        let subdir = normalize_hex(&reference.ciphertext_sha256)?;
        let result = self
            .runtime
            .download_media(&account.label, &group_id, reference)
            .await?;
        let dir = crate::media_temp::create_media_download_dir(&subdir).await?;
        // The file name comes from the (decrypted) sender-controlled media
        // reference, so write under a sanitized basename: a crafted value like
        // "../../x" must not let a download escape the per-blob temp dir.
        let path = dir.join(safe_media_filename(&result.file_name));
        // Create with 0600 atomically so the plaintext is never world-readable,
        // even momentarily (no post-write chmod TOCTOU window).
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .await?;
        use tokio::io::AsyncWriteExt as _;
        file.write_all(&result.plaintext).await?;
        Ok(AgentControlResponse::MediaDownloaded {
            path: path.to_string_lossy().into_owned(),
            media_type: result.media_type,
            file_name: result.file_name,
            size_bytes: result.size_bytes,
        })
    }
}
