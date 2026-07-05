//! `keys` (KeyPackage) command namespace handlers and output helpers.

use std::collections::HashSet;

use marmot_account::AccountHome;
use marmot_app::{AccountKeyPackageRecord, FetchedKeyPackage, MarmotApp, MarmotAppRuntime};
use serde_json::{Value, json};

use crate::{
    CommandOutput, KeyPackageCommand, WnError, account_selector_or_default, ensure_local_signing,
    npub_for_account_id, parse_public_key, relay_endpoints, relay_lists_json, resolve_account,
};

pub(crate) async fn key_package_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    key_package_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn key_package_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, WnError> {
    match command {
        KeyPackageCommand::List => {
            let account = resolve_account(account_home, account_flag)?;
            let records = runtime
                .account_key_packages(&account.label, Vec::new())
                .await?;
            let keys = records
                .into_iter()
                .map(account_key_package_record_json)
                .collect::<Vec<_>>();
            Ok(CommandOutput {
                plain: if keys.is_empty() {
                    "no key packages".to_owned()
                } else {
                    format!("{} key package(s)", keys.len())
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "keys": keys,
                }),
            })
        }
        KeyPackageCommand::Publish => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let key_package_bytes = runtime.publish_key_package(&account.label).await?;
            Ok(CommandOutput {
                plain: format!(
                    "published key package for {} bytes={}",
                    npub_for_account_id(&account.account_id_hex)?,
                    key_package_bytes
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "key_package_bytes": key_package_bytes,
                }),
            })
        }
        KeyPackageCommand::Rotate => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let key_package_bytes = runtime.rotate_key_package(&account.label).await?;
            Ok(CommandOutput {
                plain: format!(
                    "rotated key package for {} bytes={}",
                    npub_for_account_id(&account.account_id_hex)?,
                    key_package_bytes
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "key_package_bytes": key_package_bytes,
                    "rotated": true,
                }),
            })
        }
        KeyPackageCommand::Fetch {
            account,
            bootstrap_relays,
        } => {
            let account_id = account_selector_or_default(account_home, account, account_flag)?;
            let fetched = app
                .fetch_latest_key_package_for_account_id(
                    &account_id,
                    relay_endpoints(bootstrap_relays)?,
                )
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "fetched key package for {account_id} bytes={} relays={}",
                    fetched.key_package.bytes().len(),
                    fetched.source_relays.join(",")
                ),
                json: key_package_fetch_json(fetched),
            })
        }
        KeyPackageCommand::Check { pubkey } => {
            let account_id = parse_public_key(&pubkey)?;
            let fetched = app
                .fetch_latest_key_package_for_account_id(&account_id, Vec::new())
                .await?;
            Ok(CommandOutput {
                plain: format!("key package available for {account_id}"),
                json: json!({
                    "account_id": account_id,
                    "npub": npub_for_account_id(&account_id)?,
                    "available": true,
                    "key_package": key_package_fetch_json(fetched),
                }),
            })
        }
        KeyPackageCommand::Delete { event_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let deleted = runtime
                .delete_key_package(&account.label, &event_id, Vec::new())
                .await?;
            Ok(CommandOutput {
                plain: format!("deleted key package event {event_id} relays={deleted}"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "event_id": event_id,
                    "deleted": true,
                    "accepted_relays": deleted,
                }),
            })
        }
        KeyPackageCommand::DeleteAll { confirm } => {
            if !confirm {
                return Err(WnError::ConfirmationRequired {
                    command: "keys delete-all",
                    flag: "--confirm",
                    reason: "pass --confirm to publish deletion events for every relay-published KeyPackage",
                });
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let records = runtime
                .account_key_packages(&account.label, Vec::new())
                .await?;
            let mut deleted = Vec::new();
            let mut failed = Vec::new();
            let mut seen_event_ids = HashSet::new();
            let mut accepted_relays = 0_usize;
            for record in records.into_iter().filter(|record| record.relay) {
                if !seen_event_ids.insert(record.key_package_event_id.clone()) {
                    continue;
                }
                let relays = match relay_endpoints(record.source_relays.clone()) {
                    Ok(relays) => relays,
                    Err(err) => {
                        failed.push(FailedKeyPackageDeletion::from_record(&record, &err));
                        continue;
                    }
                };
                let accepted = match runtime
                    .delete_key_package(&account.label, &record.key_package_event_id, relays)
                    .await
                {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        failed.push(FailedKeyPackageDeletion::from_record(&record, &err));
                        continue;
                    }
                };
                accepted_relays += accepted;
                deleted.push(DeletedKeyPackage {
                    event_id: record.key_package_event_id,
                    key_package_id: record.key_package_id,
                    key_package_ref: record.key_package_ref_hex,
                    accepted_relays: accepted,
                });
            }
            Ok(CommandOutput {
                plain: format!(
                    "deleted {} key package event(s), failed {} relays={accepted_relays}",
                    deleted.len(),
                    failed.len()
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "deleted": deleted,
                    "deleted_count": deleted.len(),
                    "failed": failed,
                    "failed_count": failed.len(),
                    "accepted_relays": accepted_relays,
                }),
            })
        }
    }
}

#[derive(serde::Serialize)]
struct DeletedKeyPackage {
    event_id: String,
    key_package_id: String,
    key_package_ref: String,
    accepted_relays: usize,
}

#[derive(serde::Serialize)]
struct FailedKeyPackageDeletion {
    event_id: String,
    key_package_id: String,
    key_package_ref: String,
    error: String,
}

impl FailedKeyPackageDeletion {
    fn from_record(record: &AccountKeyPackageRecord, err: &impl std::fmt::Display) -> Self {
        Self {
            event_id: record.key_package_event_id.clone(),
            key_package_id: record.key_package_id.clone(),
            key_package_ref: record.key_package_ref_hex.clone(),
            error: err.to_string(),
        }
    }
}

fn account_key_package_record_json(record: AccountKeyPackageRecord) -> Value {
    json!({
        "account_label": record.account_label,
        "account_id": record.account_id_hex,
        "key_package_id": record.key_package_id,
        "key_package_ref": record.key_package_ref_hex,
        "key_package_event_id": record.key_package_event_id,
        "published_at": record.published_at,
        "key_package_bytes": record.key_package_bytes,
        "source_relays": record.source_relays,
        "local": record.local,
        "relay": record.relay,
    })
}

fn key_package_fetch_json(fetched: FetchedKeyPackage) -> Value {
    json!({
        "account_id": fetched.account_id_hex,
        "key_package_id": fetched.key_package_id,
        "key_package_ref": fetched.key_package_ref_hex,
        "key_package_event_id": fetched.key_package_event_id,
        "key_package_bytes": fetched.key_package.bytes().len(),
        "created_at": fetched.created_at,
        "source_relays": fetched.source_relays,
        "relay_lists": relay_lists_json(fetched.relay_lists),
    })
}
