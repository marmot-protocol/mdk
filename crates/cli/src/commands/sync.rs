//! `sync` command namespace handler and output helpers.

use marmot_app::{MarmotApp, SyncSummary};
use serde_json::{Value, json};

use crate::{
    CommandOutput, DmError, agent_text_stream_payload_value, display_name_for_sender,
    npub_for_account_id,
};

pub(crate) async fn sync_command(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
) -> Result<CommandOutput, DmError> {
    app.status(&account.label)?;
    let mut client = app.client(&account.label).await?;
    let summary = client.sync().await?;
    Ok(CommandOutput {
        plain: sync_plain(&summary),
        json: sync_json(app, account, summary)?,
    })
}

fn sync_plain(summary: &SyncSummary) -> String {
    let mut lines = Vec::new();
    for group_id in &summary.joined_groups {
        lines.push(format!("joined group {}", hex::encode(group_id.as_slice())));
    }
    for message in &summary.messages {
        lines.push(format!(
            "received group={} from={}: {}",
            hex::encode(message.group_id.as_slice()),
            message.sender,
            message.plaintext
        ));
    }
    if lines.is_empty() {
        if summary.events.is_empty() {
            "no new events".to_owned()
        } else {
            format!("processed {} event(s)", summary.events.len())
        }
    } else {
        lines.join("\n")
    }
}

fn sync_json(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    summary: SyncSummary,
) -> Result<Value, DmError> {
    Ok(json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex)?,
        "joined_groups": summary.joined_groups.into_iter().map(|group_id| {
            hex::encode(group_id.as_slice())
        }).collect::<Vec<_>>(),
        "messages": summary.messages.into_iter().map(|message| {
            let agent_text_stream = agent_text_stream_payload_value(
                message.kind,
                &message.tags,
                &message.plaintext,
            );
            let from_display_name = message
                .sender_display_name
                .clone()
                .or_else(|| display_name_for_sender(app, &message.sender));
            let mut value = json!({
                "message_id": message.message_id_hex,
                "direction": "received",
                "from": message.sender,
                "from_display_name": from_display_name,
                "group_id": hex::encode(message.group_id.as_slice()),
                "plaintext": message.plaintext,
                "kind": message.kind,
                "tags": message.tags,
            });
            if let Some(agent_text_stream) = agent_text_stream {
                value["agent_text_stream"] = agent_text_stream;
            }
            value
        }).collect::<Vec<_>>(),
        "events": summary.events.len(),
    }))
}
