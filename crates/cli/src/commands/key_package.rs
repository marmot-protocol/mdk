//! `keys` (KeyPackage) command namespace handlers and output helpers.

use marmot_account::AccountHome;
use marmot_app::{FetchedKeyPackage, MarmotApp, MarmotAppRuntime};
use serde_json::{Value, json};

use crate::{
    CommandOutput, DmError, KeyPackageCommand, account_selector_or_default, ensure_local_signing,
    npub_for_account_id, parse_public_key, relay_endpoints, relay_lists_json, resolve_account,
    unsupported_command,
};

pub(crate) async fn key_package_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    key_package_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn key_package_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: KeyPackageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        KeyPackageCommand::List => {
            let account = resolve_account(account_home, account_flag)?;
            let relay_lists =
                app.account_relay_list_status_for_account_id(&account.account_id_hex)?;
            let fetched = if relay_lists.nip65.relays.is_empty() {
                None
            } else {
                Some(
                    app.fetch_latest_key_package_for_account_id(
                        &account.account_id_hex,
                        relay_endpoints(relay_lists.nip65.relays.clone())?,
                    )
                    .await?,
                )
            };
            let keys = fetched
                .into_iter()
                .map(key_package_fetch_json)
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
        KeyPackageCommand::Delete { .. } => unsupported_command(
            "keys delete",
            "relay deletion for KeyPackage events is not implemented yet",
        ),
        KeyPackageCommand::DeleteAll { confirm } => {
            if !confirm {
                return unsupported_command(
                    "keys delete-all",
                    "pass --confirm once relay deletion is implemented",
                );
            }
            unsupported_command(
                "keys delete-all",
                "relay deletion for KeyPackage events is not implemented yet",
            )
        }
    }
}

fn key_package_fetch_json(fetched: FetchedKeyPackage) -> Value {
    json!({
        "account_id": fetched.account_id_hex,
        "key_package_id": fetched.key_package_id,
        "key_package_ref": fetched.key_package_ref_hex,
        "key_package_bytes": fetched.key_package.bytes().len(),
        "created_at": fetched.created_at,
        "source_relays": fetched.source_relays,
        "relay_lists": relay_lists_json(fetched.relay_lists),
    })
}
