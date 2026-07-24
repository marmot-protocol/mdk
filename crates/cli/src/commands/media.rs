//! `media` command namespace handlers and media-attachment helpers.

use std::path::{Path, PathBuf};

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppMessageQuery, AppMessageRecord, MarmotApp, MarmotAppRuntime, MediaAttachmentReference,
    MediaLocator, MediaUploadAttachmentRequest, MediaUploadRequest,
};
use serde_json::{Value, json};

use crate::{
    CommandOutput, MediaCommand, WnError, ensure_local_signing, normalize_group_id_hex,
    npub_for_account_id, resolve_account, write_private_file,
};

pub(crate) async fn media_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    media_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn media_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MediaCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
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
                WnError::InvalidMediaAttachment("upload returned no attachments".to_owned())
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
            let reference = media_attachment_for_hash(
                messages,
                &file_hash_hex,
                app.allow_loopback_blob_endpoints(),
            )?;
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
            let media = media_records_json(messages, app.allow_loopback_blob_endpoints());
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

fn media_records_json(messages: Vec<AppMessageRecord>, allow_loopback_http: bool) -> Vec<Value> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then(|| message.plaintext.clone());
        for (attachment_index, reference) in
            media_attachments_from_message(&message, allow_loopback_http)
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
    records
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
    allow_loopback_http: bool,
) -> Result<MediaAttachmentReference, WnError> {
    for message in messages {
        for reference in media_attachments_from_message(&message, allow_loopback_http) {
            if reference.plaintext_sha256 == file_hash_hex {
                return Ok(reference);
            }
        }
    }
    Err(WnError::MediaAttachmentNotFound(file_hash_hex.to_owned()))
}

fn media_attachments_from_message(
    message: &AppMessageRecord,
    allow_loopback_http: bool,
) -> Vec<MediaAttachmentReference> {
    // Rejection is attachment-local: a malformed sibling must not abort list or
    // download before a later valid reference is considered. Match the UniFFI
    // `list_media` / timeline projection path, which uses `filter_map`.
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| {
            media_attachment_from_imeta_tag(tag, message.source_epoch, allow_loopback_http).ok()
        })
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
    allow_loopback_http: bool,
) -> Result<MediaAttachmentReference, WnError> {
    let source_epoch =
        source_epoch.ok_or_else(|| WnError::InvalidMediaAttachment("source_epoch".to_owned()))?;
    marmot_app::media_attachment_from_imeta_tag(tag, Some(source_epoch), allow_loopback_http)
        .map_err(|error| WnError::InvalidMediaAttachment(error.to_string()))
}

fn normalize_sha256_hex(value: &str) -> Result<String, WnError> {
    let decoded = hex::decode(value)?;
    if decoded.len() != 32 {
        return Err(WnError::InvalidMediaAttachment(
            "file hash must be 32 bytes".to_owned(),
        ));
    }
    Ok(hex::encode(decoded))
}

fn media_file_name(path: &Path) -> Result<String, WnError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| WnError::InvalidMediaAttachment("file name".to_owned()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared golden imeta fixtures also drive marmot-app and marmot-uniffi
    /// agreement tests.
    fn shared_media_fixture_cases(file: &str) -> Vec<Value> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/encrypted-media")
            .join(file);
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read media fixture {}: {err}", path.display())),
        )
        .expect("media fixture file is valid JSON");
        doc["cases"].as_array().expect("fixture cases").clone()
    }

    /// The CLI resolves inbound `imeta` tags through the same Rust parser as
    /// app-core and the bindings; this locks the agreement on the shared
    /// fixtures so a divergent CLI-side wrapper (the pre-#1080 hand-written
    /// parser regressing) fails loudly.
    #[test]
    fn cli_media_validation_agrees_with_shared_golden_fixtures() {
        for file in ["imeta-v1.json", "imeta-v2.json"] {
            for case in shared_media_fixture_cases(file) {
                let name = case["name"].as_str().expect("fixture case name");
                let tag: Vec<String> = case["tag"]
                    .as_array()
                    .expect("fixture tag")
                    .iter()
                    .map(|field| field.as_str().expect("fixture tag field").to_owned())
                    .collect();
                let source_epoch = case["source_epoch"].as_u64().expect("fixture source_epoch");
                let valid = case["valid"].as_bool().expect("fixture valid flag");
                let result = media_attachment_from_imeta_tag(&tag, Some(source_epoch), false);
                match result {
                    Ok(reference) => {
                        assert!(valid, "{file}/{name}: CLI accepted a rejection fixture");
                        let expected = &case["expected"];
                        assert_eq!(
                            reference.version,
                            expected["version"].as_str().unwrap(),
                            "{file}/{name} version"
                        );
                        assert_eq!(
                            reference.source_epoch, source_epoch,
                            "{file}/{name} source_epoch"
                        );
                    }
                    Err(err) => {
                        assert!(
                            !valid,
                            "{file}/{name}: CLI rejected a golden fixture: {err}"
                        );
                        let needle = case["error_contains"].as_str().expect("error_contains");
                        assert!(
                            err.to_string().contains(needle),
                            "{file}/{name} error must mention {needle:?}, got: {err}"
                        );
                    }
                }
            }
        }
    }

    fn sample_message(tags: Vec<Vec<String>>) -> AppMessageRecord {
        AppMessageRecord {
            message_id_hex: "aa".repeat(32),
            direction: "incoming".to_owned(),
            group_id_hex: "bb".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "caption".to_owned(),
            kind: 9,
            tags,
            source_epoch: Some(7),
            retention: None,
            recorded_at: 10,
            received_at: 11,
            insert_order: 0,
        }
    }

    fn valid_cli_imeta_tag(byte: u8, file_name: &str) -> Vec<String> {
        vec![
            "imeta".to_owned(),
            "v encrypted-media-v1".to_owned(),
            format!(
                "locator blossom-v1 https://media.example/{}.bin",
                hex::encode([byte; 32])
            ),
            format!("ciphertext_sha256 {}", hex::encode([byte; 32])),
            format!(
                "plaintext_sha256 {}",
                hex::encode([byte.wrapping_add(1); 32])
            ),
            format!("nonce {}", hex::encode([byte; 12])),
            "m image/png".to_owned(),
            format!("filename {file_name}"),
        ]
    }

    #[test]
    fn cli_media_list_keeps_valid_siblings_when_one_imeta_is_malformed() {
        let malformed = vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()];
        let message = sample_message(vec![
            valid_cli_imeta_tag(0x11, "ok.png"),
            malformed,
            valid_cli_imeta_tag(0x22, "also-ok.png"),
        ]);

        let references = media_attachments_from_message(&message, false);
        assert_eq!(
            references
                .iter()
                .map(|reference| reference.file_name.as_str())
                .collect::<Vec<_>>(),
            ["ok.png", "also-ok.png"]
        );

        let later = media_attachment_for_hash(vec![message], &hex::encode([0x23; 32]), false)
            .expect("download lookup must reach the later valid sibling");
        assert_eq!(later.file_name, "also-ok.png");
    }
}
