//! `create-identity` / `login` / `whoami` / `account(s)` command namespace handlers and helpers.

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use marmot_app::{
    AccountRelayListStatus, AccountSetupRequest, AccountSetupResult, AppError, AppStatus,
    MarmotApp, MissingRelayListKind,
};
use serde_json::{Value, json};

use crate::{
    AccountCommand, CliRuntimeInfo, CommandOutput, DmError, SecretStoreKind,
    account_selector_or_default, is_nostr_secret, npub_for_account_id, parse_public_key,
    profile_display_name, relay_endpoints, relay_lists_json, resolve_account, unsupported_command,
    validate_materialized_secret_identity,
};

pub(crate) async fn identity_create_command(
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    relay: Option<String>,
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<CommandOutput, DmError> {
    create_or_import_account_command(
        app,
        None,
        default_relays,
        bootstrap_relays,
        false,
        true,
        false,
        runtime_info,
        relay,
    )
    .await
}

pub(crate) async fn identity_login_command(
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    identity: Option<String>,
    nsec_stdin: bool,
    relay: Option<String>,
    default_relays: Vec<String>,
    bootstrap_relays: Vec<String>,
) -> Result<CommandOutput, DmError> {
    validate_materialized_secret_identity("login", &identity, nsec_stdin)?;
    let Some(identity) = identity else {
        return Err(DmError::MissingLoginIdentity);
    };
    create_or_import_account_command(
        app,
        Some(identity),
        default_relays,
        bootstrap_relays,
        true,
        true,
        nsec_stdin,
        runtime_info,
        relay,
    )
    .await
}

pub(crate) fn whoami_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime_info: CliRuntimeInfo,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    if account_flag.is_some() {
        let account = resolve_account(account_home, account_flag)?;
        let status = if account.local_signing {
            dm_status_json(app.status(&account.label)?, &runtime_info)?
        } else {
            public_account_status_json(
                &account,
                app.account_relay_list_status_for_account_id(&account.account_id_hex)?,
            )?
        };
        return Ok(CommandOutput {
            plain: serde_json::to_string_pretty(&status)
                .expect("JSON response serialization cannot fail"),
            json: status,
        });
    }

    let accounts = account_home.accounts()?;
    let accounts_json = accounts
        .into_iter()
        .map(|account| account_summary_json(app, account))
        .collect::<Result<Vec<_>, _>>()?;
    let plain = if accounts_json.is_empty() {
        "no accounts".to_owned()
    } else {
        accounts_json
            .iter()
            .map(|account| {
                format!(
                    "{} {} local-signing={}",
                    account_display_name_or_npub(account),
                    account
                        .get("account_id")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    account
                        .get("local_signing")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(CommandOutput {
        plain,
        json: json!({ "accounts": accounts_json }),
    })
}

pub(crate) fn logout_command(
    account_home: &AccountHome,
    pubkey: String,
) -> Result<CommandOutput, DmError> {
    let account_id = parse_public_key(&pubkey)?;
    account_home.remove_account(&account_id)?;
    Ok(CommandOutput {
        plain: format!("logged out {}", npub_for_account_id(&account_id)?),
        json: json!({
            "account_id": account_id,
            "npub": npub_for_account_id(&account_id)?,
            "logged_out": true,
        }),
    })
}

pub(crate) fn export_nsec_command(_pubkey: String) -> Result<CommandOutput, DmError> {
    unsupported_command(
        "export-nsec",
        "Darkmatter CLI policy forbids printing private keys",
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_or_import_account_command(
    app: &MarmotApp,
    identity: Option<String>,
    mut default_relays: Vec<String>,
    mut bootstrap_relays: Vec<String>,
    publish_missing_relay_lists: bool,
    publish_initial_key_package: bool,
    nsec_stdin: bool,
    _runtime_info: CliRuntimeInfo,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    validate_materialized_secret_identity("account create", &identity, nsec_stdin)?;
    let global_relay_defaults =
        apply_global_relay_defaults(&mut default_relays, &mut bootstrap_relays, relay);
    let imports_private_key = identity.as_deref().is_some_and(is_nostr_secret);
    let creates_new_private_key = identity.is_none();
    let adds_public_account = identity
        .as_deref()
        .is_some_and(|value| !is_nostr_secret(value));
    if creates_new_private_key && default_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if imports_private_key && default_relays.is_empty() && bootstrap_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if adds_public_account && bootstrap_relays.is_empty() && default_relays.is_empty() {
        return Err(DmError::MissingRelay);
    }
    if adds_public_account && !default_relays.is_empty() && !global_relay_defaults.default_relays {
        return Err(DmError::PublicAccountCannotSign);
    }

    let default_relays = relay_endpoints(default_relays)?;
    let bootstrap_relays = relay_endpoints(bootstrap_relays)?;
    let setup = app
        .runtime()
        .create_or_import_account(AccountSetupRequest {
            identity,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
            publish_initial_key_package,
        })
        .await
        .map_err(map_account_setup_error)?;

    account_setup_command_output(setup)
}

pub(crate) fn account_setup_command_output(
    setup: AccountSetupResult,
) -> Result<CommandOutput, DmError> {
    let key_package_plain = setup
        .key_package_bytes
        .map(|bytes| format!(" key-package-bytes={bytes}"))
        .unwrap_or_default();
    Ok(CommandOutput {
        plain: format!(
            "created identity {} local-signing={} relay-lists={}{}",
            npub_for_account_id(&setup.account.account_id_hex)?,
            setup.account.local_signing,
            relay_setup_plain(&setup.relay_lists),
            key_package_plain
        ),
        json: json!({
            "account_id": setup.account.account_id_hex,
            "npub": npub_for_account_id(&setup.account.account_id_hex)?,
            "local_signing": setup.account.local_signing,
            "relay_lists": relay_lists_json(setup.relay_lists),
            "key_package": setup.key_package_bytes.map(|bytes| json!({
                "published": true,
                "bytes": bytes,
            })),
            "profile": setup.profile,
        }),
    })
}

pub(crate) fn map_account_setup_error(err: AppError) -> DmError {
    if let AppError::MissingRelayLists(missing) = &err {
        let status = missing_relay_list_status(missing.clone());
        return DmError::MissingRelayLists(missing.clone(), Box::new(status));
    }
    err.into()
}

fn missing_relay_list_status(missing: Vec<MissingRelayListKind>) -> AccountRelayListStatus {
    AccountRelayListStatus {
        complete: false,
        missing,
        default_relays: Vec::new(),
        bootstrap_relays: Vec::new(),
        nip65: marmot_app::AccountRelayListState {
            kind: 10002,
            relays: Vec::new(),
        },
        inbox: marmot_app::AccountRelayListState {
            kind: 10050,
            relays: Vec::new(),
        },
    }
}

pub(crate) async fn account_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: AccountCommand,
    runtime_info: CliRuntimeInfo,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        AccountCommand::Create {
            identity,
            nsec_stdin,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
        } => {
            create_or_import_account_command(
                app,
                identity,
                default_relays,
                bootstrap_relays,
                publish_missing_relay_lists,
                false,
                nsec_stdin,
                runtime_info,
                relay,
            )
            .await
        }
        AccountCommand::List => {
            let accounts = account_home.accounts()?;
            let accounts_json = accounts
                .into_iter()
                .map(|account| account_summary_json(app, account))
                .collect::<Result<Vec<_>, _>>()?;
            let plain = if accounts_json.is_empty() {
                "no accounts".to_owned()
            } else {
                accounts_json
                    .iter()
                    .map(|account| {
                        format!(
                            "{} {} local-signing={}",
                            account_display_name_or_npub(account),
                            account
                                .get("account_id")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                            account
                                .get("local_signing")
                                .and_then(Value::as_bool)
                                .unwrap_or(false)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(CommandOutput {
                plain,
                json: json!({ "accounts": accounts_json }),
            })
        }
        AccountCommand::Status { account } => {
            let account = resolve_account(account_home, account.or(account_flag))?;
            if !account.local_signing {
                let relay_lists =
                    app.account_relay_list_status_for_account_id(&account.account_id_hex)?;
                let json = public_account_status_json(&account, relay_lists)?;
                return Ok(CommandOutput {
                    plain: serde_json::to_string_pretty(&json)
                        .expect("JSON response serialization cannot fail"),
                    json,
                });
            }
            let status = app.status(&account.label)?;
            let json = dm_status_json(status, &runtime_info)?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&json)
                    .expect("JSON response serialization cannot fail"),
                json,
            })
        }
        AccountCommand::RelayLists {
            account,
            bootstrap_relays,
        } => {
            let account_id = account_selector_or_default(account_home, account, account_flag)?;
            let relay_lists = relay_list_status_for_account_id(
                app,
                &account_id,
                relay_endpoints(bootstrap_relays)?,
            )
            .await?;
            Ok(CommandOutput {
                plain: relay_setup_plain(&relay_lists),
                json: json!({
                    "account_id": account_id,
                    "npub": npub_for_account_id(&account_id)?,
                    "relay_lists": relay_lists_json(relay_lists),
                }),
            })
        }
    }
}

fn relay_setup_plain(status: &AccountRelayListStatus) -> String {
    if status.complete {
        "complete".to_owned()
    } else {
        format!(
            "missing:{}",
            status
                .missing
                .iter()
                .map(|k| k.token())
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

async fn relay_list_status_for_account_id(
    app: &MarmotApp,
    account_id: &str,
    bootstrap_relays: Vec<TransportEndpoint>,
) -> Result<AccountRelayListStatus, DmError> {
    if bootstrap_relays.is_empty() {
        Ok(app.account_relay_list_status_for_account_id(account_id)?)
    } else {
        Ok(app
            .fetch_account_relay_list_status_for_account_id(account_id, bootstrap_relays)
            .await?)
    }
}

fn account_summary_json(
    app: &MarmotApp,
    account: marmot_account::AccountSummary,
) -> Result<Value, DmError> {
    let profile = app
        .directory_entry_for_account_id(&account.account_id_hex)
        .ok()
        .flatten()
        .and_then(|entry| entry.profile);
    let display_name = profile_display_name(profile.as_ref());
    Ok(json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex)?,
        "display_name": display_name,
        "profile": profile,
        "local_signing": account.local_signing,
    }))
}

fn account_display_name_or_npub(account: &Value) -> &str {
    account
        .get("display_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| account.get("npub").and_then(Value::as_str))
        .unwrap_or("")
}

fn dm_status_json(status: AppStatus, runtime_info: &CliRuntimeInfo) -> Result<Value, DmError> {
    Ok(json!({
        "account_id": status.account_id_hex,
        "npub": npub_for_account_id(&status.account_id_hex)?,
        "local_signing": true,
        "transport": status.transport,
        "groups": status.groups,
        "seen_events": status.seen_events,
        "counts": {
            "groups": status.group_count,
            "messages": status.message_count,
            "seen_events": status.seen_events,
        },
        "secret_store": secret_store_json(runtime_info),
        "projections": status.projections,
        "relay_lists": relay_lists_json(status.relay_lists),
    }))
}

fn secret_store_json(runtime_info: &CliRuntimeInfo) -> Value {
    match runtime_info.secret_store {
        SecretStoreKind::File => json!({
            "backend": runtime_info.secret_store.as_str(),
        }),
        SecretStoreKind::Keychain => json!({
            "backend": runtime_info.secret_store.as_str(),
            "service": runtime_info.keychain_service,
        }),
    }
}

fn public_account_status_json(
    account: &marmot_account::AccountSummary,
    relay_lists: AccountRelayListStatus,
) -> Result<Value, DmError> {
    Ok(json!({
        "account_id": account.account_id_hex,
        "npub": npub_for_account_id(&account.account_id_hex)?,
        "local_signing": false,
        "relay_lists": relay_lists_json(relay_lists),
    }))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GlobalRelayDefaults {
    pub(crate) default_relays: bool,
    pub(crate) bootstrap_relays: bool,
}

pub(crate) fn apply_global_relay_defaults(
    default_relays: &mut Vec<String>,
    bootstrap_relays: &mut Vec<String>,
    relay: Option<String>,
) -> GlobalRelayDefaults {
    let mut applied = GlobalRelayDefaults::default();
    let Some(relay) = relay.map(|relay| relay.trim().to_owned()) else {
        return applied;
    };
    if relay.is_empty() {
        return applied;
    }
    if default_relays.is_empty() {
        default_relays.push(relay.clone());
        applied.default_relays = true;
    }
    if bootstrap_relays.is_empty() {
        bootstrap_relays.push(relay);
        applied.bootstrap_relays = true;
    }
    applied
}
