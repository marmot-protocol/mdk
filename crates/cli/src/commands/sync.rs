//! `sync` command namespace handler and output helpers.

use marmot_app::{MarmotApp, MarmotAppRuntime, ReceivedMessage, SyncFailure, SyncSummary};
use serde_json::{Value, json};

use crate::{
    CommandOutput, WnError, agent_text_stream_payload_value, display_name_for_sender,
    error::SyncCommandError, npub_for_account_id,
};

pub(crate) async fn sync_command(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
) -> Result<CommandOutput, WnError> {
    app.status(&account.label)?;
    let mut client = app.client(&account.label).await?;
    let summary = match client.sync_with_partial_progress().await {
        Ok(summary) => summary,
        Err(failure) => return Err(sync_failure_error(app, account, failure)),
    };
    sync_command_output(app, account, summary)
}

pub(crate) async fn sync_command_with_runtime(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
) -> Result<CommandOutput, WnError> {
    app.status(&account.label)?;
    let summary = match runtime.sync_with_partial_progress(&account.label).await {
        Ok(summary) => summary,
        Err(failure) => return Err(sync_failure_error(app, account, failure)),
    };
    sync_command_output(app, account, summary)
}

fn sync_command_output(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    summary: SyncSummary,
) -> Result<CommandOutput, WnError> {
    Ok(CommandOutput {
        plain: sync_plain(&summary),
        json: sync_json(app, account, summary)?,
    })
}

fn sync_failure_error(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    failure: SyncFailure,
) -> WnError {
    let SyncFailure {
        partial_summary,
        source,
        ..
    } = failure;
    let partial_plain = partial_sync_plain(&partial_summary);
    // Rendering the applied prefix is secondary to the sync failure. Account
    // records normally guarantee a valid npub, but preserve the source error
    // and the rest of the machine-readable prefix even if that invariant is
    // broken instead of replacing the operation failure with a render error.
    let npub = npub_for_account_id(&account.account_id_hex).ok();
    let partial_json = partial_sync_json_value(app, &account, partial_summary, npub);
    WnError::Sync(Box::new(SyncCommandError {
        source,
        partial_plain,
        partial_json,
    }))
}

fn sync_plain(summary: &SyncSummary) -> String {
    sync_plain_with_empty(summary, "no new events")
}

fn sync_plain_with_empty(summary: &SyncSummary, empty: &str) -> String {
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
    if !summary.events.is_empty() {
        lines.push(format!("processed {} event(s)", summary.events.len()));
    }
    if !summary.projection_updates.is_empty() {
        lines.push(format!(
            "processed {} projection update(s)",
            summary.projection_updates.len()
        ));
    }
    if !summary.epoch_stall_escalations.is_empty() {
        lines.push(format!(
            "reported {} epoch stall escalation(s)",
            summary.epoch_stall_escalations.len()
        ));
    }
    if lines.is_empty() {
        empty.to_owned()
    } else {
        lines.join("\n")
    }
}

fn sync_json(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
    summary: SyncSummary,
) -> Result<Value, WnError> {
    Ok(json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex)?,
        "joined_groups": summary.joined_groups.into_iter().map(|group_id| {
            hex::encode(group_id.as_slice())
        }).collect::<Vec<_>>(),
        "messages": sync_messages_json(app, summary.messages),
        "events": summary.events.len(),
        "projection_updates": summary.projection_updates.len(),
        "epoch_stall_escalations": summary.epoch_stall_escalations.len(),
    }))
}

fn sync_messages_json(app: &MarmotApp, messages: Vec<ReceivedMessage>) -> Vec<Value> {
    messages
        .into_iter()
        .map(|message| {
            let agent_text_stream =
                agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext);
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
        })
        .collect()
}

fn partial_sync_plain(summary: &SyncSummary) -> String {
    sync_plain_with_empty(summary, "no completed sync progress")
}

fn partial_sync_json_value(
    app: &MarmotApp,
    account: &marmot_account::AccountSummary,
    summary: SyncSummary,
    npub: Option<String>,
) -> Value {
    json!({
        "account_id": account.account_id_hex,
        "npub": npub,
        "joined_groups": summary.joined_groups.into_iter().map(|group_id| {
            hex::encode(group_id.as_slice())
        }).collect::<Vec<_>>(),
        "messages": sync_messages_json(app, summary.messages),
        "events": summary.events.len(),
        "projection_updates": summary.projection_updates.len(),
        "epoch_stall_escalations": summary.epoch_stall_escalations.len(),
    })
}

#[cfg(test)]
mod tests {
    use cgka_traits::GroupId;
    use marmot_account::AccountHome;
    use marmot_app::{AppError, EpochStallEscalation, ReceivedMessage, SyncFailure};

    use super::*;
    use crate::wn_error_json;

    #[test]
    fn sync_failure_error_preserves_partial_summary_for_json_and_plain_output() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let failure = SyncFailure::new(
            SyncSummary {
                messages: vec![ReceivedMessage {
                    message_id_hex: "11".repeat(32),
                    source_message_id_hex: "22".repeat(32),
                    sender: account.account_id_hex.clone(),
                    sender_display_name: Some("Alice".to_owned()),
                    group_id: GroupId::new(vec![3; 16]),
                    source_epoch: 1,
                    retention: None,
                    plaintext: "durable before sync failure".to_owned(),
                    kind: 9,
                    tags: Vec::new(),
                    recorded_at: 1,
                    received_at: 2,
                }],
                epoch_stall_escalations: vec![EpochStallEscalation {
                    group_id: GroupId::new(vec![4; 16]),
                    stalled_epoch: 7,
                    arms: 3,
                }],
                ..Default::default()
            },
            AppError::BlockingTask("injected sync failure".to_owned()),
        );

        let error = sync_failure_error(&app, account, failure);
        let rendered = wn_error_json(&error);

        assert_eq!(rendered["code"], "command_failed");
        assert!(rendered.get("cause").is_none());
        assert_eq!(
            rendered["partial"]["messages"][0]["plaintext"],
            "durable before sync failure"
        );
        assert_eq!(rendered["partial"]["epoch_stall_escalations"], 1);
        assert_eq!(error.to_string(), "sync failed");
        assert!(!format!("{error:?}").contains("durable before sync failure"));
        let plain = crate::command_output_result(false, Err(error));
        assert!(plain.stderr.contains("durable before sync failure"));
        assert!(
            plain
                .stderr
                .contains("reported 1 epoch stall escalation(s)")
        );
        assert!(plain.stderr.contains("injected sync failure"));
    }

    #[test]
    fn sync_failure_rendering_never_masks_the_source_error() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let account = marmot_account::AccountSummary {
            label: "broken".to_owned(),
            account_id_hex: "not-a-public-key".to_owned(),
            local_signing: true,
            external_signing: false,
            signed_out: false,
        };
        let failure = SyncFailure::new(
            SyncSummary::default(),
            AppError::BlockingTask("original sync failure".to_owned()),
        );

        let error = sync_failure_error(&app, account, failure);
        let rendered = wn_error_json(&error);

        assert!(
            rendered["message"]
                .as_str()
                .is_some_and(|message| message.contains("original sync failure"))
        );
        assert!(rendered["partial"]["npub"].is_null());
        assert_eq!(error.to_string(), "sync failed");
    }

    #[test]
    fn successful_sync_output_reports_all_summary_counts() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let summary = SyncSummary {
            epoch_stall_escalations: vec![EpochStallEscalation {
                group_id: GroupId::new(vec![4; 16]),
                stalled_epoch: 7,
                arms: 3,
            }],
            ..Default::default()
        };

        assert_eq!(sync_plain(&summary), "reported 1 epoch stall escalation(s)");
        let rendered = sync_json(&app, account, summary).unwrap();
        assert_eq!(rendered["projection_updates"], 0);
        assert_eq!(rendered["epoch_stall_escalations"], 1);
        assert_eq!(rendered["events"], 0);
    }
}
