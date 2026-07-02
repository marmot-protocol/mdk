//! `media` command namespace handlers and media-attachment helpers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppMessageQuery, AppMessageRecord, MarmotApp, MarmotAppRuntime, MediaAttachmentReference,
    MediaLocator, MediaUploadAttachmentRequest, MediaUploadRequest,
};
use serde_json::{Value, json};

use crate::{
    CommandOutput, DmError, MediaCommand, ensure_local_signing, normalize_group_id_hex,
    npub_for_account_id, resolve_account, write_private_file,
};

pub(crate) async fn media_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    media_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn media_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MediaCommand::Upload {
            group,
            file_path,
            send,
            message,
            media_type,
            server,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let path = PathBuf::from(&file_path);
            let plaintext = std::fs::read(&path)?;
            let file_name = media_file_name(&path)?;
            let media_type = media_type.unwrap_or_else(|| guess_media_type(&path).to_owned());
            let upload = runtime
                .upload_media(
                    &account.account_id_hex,
                    &group_id,
                    MediaUploadRequest {
                        attachments: vec![MediaUploadAttachmentRequest {
                            file_name,
                            media_type,
                            plaintext,
                            dim: None,
                            thumbhash: None,
                        }],
                        caption: message,
                        send,
                        blossom_server: server,
                    },
                )
                .await?;
            let first = upload.attachments.first().ok_or_else(|| {
                DmError::InvalidMediaAttachment("upload returned no attachments".to_owned())
            })?;
            Ok(CommandOutput {
                plain: if upload.sent.is_some() {
                    format!("uploaded and sent {}", first.reference.file_name)
                } else {
                    format!("uploaded {}", first.reference.file_name)
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "attachments": upload.attachments.iter().map(media_upload_attachment_json).collect::<Vec<_>>(),
                    "sent": upload.sent.map(send_summary_json),
                }),
            })
        }
        MediaCommand::Download {
            group,
            file_hash,
            output,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let file_hash_hex = normalize_sha256_hex(&file_hash)?;
            let messages = runtime.messages_with_query(
                &account.account_id_hex,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let reference = media_attachment_for_hash(messages, &file_hash_hex)?;
            let output_path = media_output_path(output, &reference.file_name);
            let download = runtime
                .download_media(&account.account_id_hex, &group_id, reference.clone())
                .await?;
            write_private_file(&output_path, &download.plaintext)?;
            Ok(CommandOutput {
                plain: output_path.display().to_string(),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "media": media_attachment_json(&reference),
                    "output_path": output_path.display().to_string(),
                    "size_bytes": download.size_bytes,
                }),
            })
        }
        MediaCommand::List { group } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let messages = runtime.messages_with_query(
                &account.account_id_hex,
                AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )?;
            let media = media_records_json(messages)?;
            Ok(CommandOutput {
                plain: if media.is_empty() {
                    "no media".to_owned()
                } else {
                    media
                        .iter()
                        .filter_map(|item| item.get("file_name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "group_id": group_id_hex,
                    "media": media,
                }),
            })
        }
    }
}

fn media_records_json(messages: Vec<AppMessageRecord>) -> Result<Vec<Value>, DmError> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then(|| message.plaintext.clone());
        for (attachment_index, reference) in media_attachments_from_message(&message)?
            .into_iter()
            .enumerate()
        {
            records.push(json!({
                "message_id": message.message_id_hex,
                "attachment_index": attachment_index,
                "direction": message.direction,
                "group_id": message.group_id_hex,
                "from": message.sender,
                "media": media_attachment_json(&reference),
                "locators": media_locators_json(&reference.locators),
                "ciphertext_sha256": reference.ciphertext_sha256,
                "plaintext_sha256": reference.plaintext_sha256,
                "file_name": reference.file_name,
                "nonce_hex": reference.nonce_hex,
                "version": reference.version,
                "media_type": reference.media_type,
                "source_epoch": reference.source_epoch,
                "dim": reference.dim,
                "thumbhash": reference.thumbhash,
                "caption": caption,
                "recorded_at": message.recorded_at,
                "received_at": message.received_at,
            }));
        }
    }
    Ok(records)
}

fn media_upload_attachment_json(attachment: &marmot_app::MediaUploadAttachmentResult) -> Value {
    json!({
        "media": media_attachment_json(&attachment.reference),
        "encrypted_size_bytes": attachment.encrypted_size_bytes,
    })
}

fn media_attachment_json(reference: &MediaAttachmentReference) -> Value {
    json!({
        "locators": media_locators_json(&reference.locators),
        "ciphertext_sha256": reference.ciphertext_sha256,
        "plaintext_sha256": reference.plaintext_sha256,
        "file_name": reference.file_name,
        "nonce_hex": reference.nonce_hex,
        "version": reference.version,
        "media_type": reference.media_type,
        "source_epoch": reference.source_epoch,
        "dim": reference.dim,
        "thumbhash": reference.thumbhash,
    })
}

fn media_locators_json(locators: &[MediaLocator]) -> Vec<Value> {
    locators
        .iter()
        .map(|locator| {
            json!({
                "kind": locator.kind,
                "value": locator.value,
            })
        })
        .collect()
}

fn send_summary_json(summary: marmot_app::SendSummary) -> Value {
    json!({
        "published": summary.published,
        "message_ids": summary.message_ids,
    })
}

fn media_attachment_for_hash(
    messages: Vec<AppMessageRecord>,
    file_hash_hex: &str,
) -> Result<MediaAttachmentReference, DmError> {
    for message in messages {
        for reference in media_attachments_from_message(&message)? {
            if reference.plaintext_sha256 == file_hash_hex {
                return Ok(reference);
            }
        }
    }
    Err(DmError::MediaAttachmentNotFound(file_hash_hex.to_owned()))
}

fn media_attachments_from_message(
    message: &AppMessageRecord,
) -> Result<Vec<MediaAttachmentReference>, DmError> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .map(|tag| media_attachment_from_imeta_tag(tag, message.source_epoch))
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Result<MediaAttachmentReference, DmError> {
    let mut locators = Vec::new();
    let mut fields = HashMap::new();
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return Err(DmError::InvalidMediaAttachment("blurhash".to_owned()));
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest
                .split_once(' ')
                .ok_or_else(|| DmError::InvalidMediaAttachment("locator".to_owned()))?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        if let Some((key, value)) = field.split_once(' ') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    let required = |key: &'static str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
            .ok_or(DmError::InvalidMediaAttachment(key.to_owned()))
    };
    Ok(MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256")?,
        plaintext_sha256: required("plaintext_sha256")?,
        nonce_hex: required("nonce")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
        source_epoch: source_epoch
            .ok_or_else(|| DmError::InvalidMediaAttachment("source_epoch".to_owned()))?,
        dim: fields.get("dim").cloned(),
        thumbhash: fields.get("thumbhash").cloned(),
    })
}

fn normalize_sha256_hex(value: &str) -> Result<String, DmError> {
    let decoded = hex::decode(value)?;
    if decoded.len() != 32 {
        return Err(DmError::InvalidMediaAttachment(
            "file hash must be 32 bytes".to_owned(),
        ));
    }
    Ok(hex::encode(decoded))
}

fn media_file_name(path: &Path) -> Result<String, DmError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DmError::InvalidMediaAttachment("file name".to_owned()))
}

fn media_output_path(output: Option<String>, file_name: &str) -> PathBuf {
    output.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(
            Path::new(file_name)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("media.bin"),
        )
    })
}

fn guess_media_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("mp4") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("wav") => "audio/wav",
        Some("ogg") => "audio/ogg",
        Some("txt") => "text/plain",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}
