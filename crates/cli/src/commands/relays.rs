//! `relays` command namespace handlers and relay-type helpers.

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use marmot_app::{AccountRelayListStatus, MarmotApp, MarmotAppRuntime};
use serde_json::json;

use crate::{
    CommandOutput, DmError, RelaysCommand, ensure_local_signing, npub_for_account_id,
    relay_endpoints, relay_lists_json, replaceable_list_inconclusive, resolve_account,
    unsupported_command, validate_relay_url,
};

pub(crate) async fn relays_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: RelaysCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    relays_command_with_runtime(account_home, app, &runtime, command, account_flag, relay).await
}

pub(crate) async fn relays_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: RelaysCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    match command {
        RelaysCommand::List { relay_type } => {
            let status = app.account_relay_list_status(&account.label)?;
            let relays = relays_for_type(&status, relay_type.as_deref())?;
            Ok(CommandOutput {
                plain: if relays.is_empty() {
                    "no relays".to_owned()
                } else {
                    relays.join("\n")
                },
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "relay_type": relay_type,
                    "relays": relays,
                    "relay_lists": relay_lists_json(status),
                }),
            })
        }
        RelaysCommand::Add { url, relay_type } => {
            update_relay_list(app, runtime, account, relay, relay_type, url, true).await
        }
        RelaysCommand::Remove { url, relay_type } => {
            update_relay_list(app, runtime, account, relay, relay_type, url, false).await
        }
    }
}

async fn update_relay_list(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account: marmot_account::AccountSummary,
    relay: Option<String>,
    relay_type: String,
    url: String,
    add: bool,
) -> Result<CommandOutput, DmError> {
    let relay_type = normalize_relay_type(&relay_type)?;
    let url = validate_relay_url(&url)?;
    let explicit_bootstrap = relay.map(validate_relay_url).transpose()?;
    let cached_status = app.account_relay_list_status(&account.label)?;
    let source_relays = if let Some(relay) = explicit_bootstrap.as_ref() {
        vec![TransportEndpoint(relay.clone())]
    } else if !cached_status.bootstrap_relays.is_empty() {
        relay_endpoints(cached_status.bootstrap_relays.clone())?
    } else {
        relay_endpoints(relays_for_type(&cached_status, None)?)?
    };
    if source_relays.is_empty() {
        return Err(replaceable_list_inconclusive(
            &format!("relays:{relay_type}"),
            &account.account_id_hex,
            &source_relays,
        ));
    }
    let status = app
        .fetch_current_account_relay_list_status_for_account_id(
            &account.account_id_hex,
            source_relays.clone(),
            Some(&relay_type),
        )
        .await?
        .ok_or_else(|| {
            replaceable_list_inconclusive(
                &format!("relays:{relay_type}"),
                &account.account_id_hex,
                &source_relays,
            )
        })?;
    let mut relays = relays_for_type(&status, Some(&relay_type))?;
    if add {
        if !relays.contains(&url) {
            relays.push(url.clone());
        }
    } else {
        relays.retain(|relay| relay != &url);
    }
    relays.sort();
    relays.dedup();
    let publish_relays = relay_endpoints(relays.clone())?;
    let bootstrap = explicit_bootstrap
        .or_else(|| source_relays.first().map(|endpoint| endpoint.0.clone()))
        .or_else(|| relays.first().cloned())
        .ok_or(DmError::MissingRelay)?;
    let bootstrap_relays = vec![TransportEndpoint(bootstrap)];
    let status = runtime
        .publish_account_relay_list_kind(
            &account.label,
            &relay_type,
            publish_relays,
            bootstrap_relays,
        )
        .await?;
    Ok(CommandOutput {
        plain: relays.join("\n"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub_for_account_id(&account.account_id_hex)?,
            "relay_type": relay_type,
            "relays": relays,
            "relay_lists": relay_lists_json(status),
        }),
    })
}

fn relays_for_type(
    status: &AccountRelayListStatus,
    relay_type: Option<&str>,
) -> Result<Vec<String>, DmError> {
    match relay_type.map(normalize_relay_type).transpose()?.as_deref() {
        Some("nip65") => Ok(status.nip65.relays.clone()),
        Some("inbox") => Ok(status.inbox.relays.clone()),
        None => {
            let mut relays = status.default_relays.clone();
            relays.extend(status.inbox.relays.clone());
            relays.sort();
            relays.dedup();
            Ok(relays)
        }
        Some(_) => unreachable!("normalize_relay_type constrains values"),
    }
}

fn normalize_relay_type(value: &str) -> Result<String, DmError> {
    match value {
        "nip65" => Ok("nip65".to_owned()),
        "inbox" => Ok("inbox".to_owned()),
        _ => unsupported_command("relays", "relay type must be nip65 or inbox"),
    }
}
