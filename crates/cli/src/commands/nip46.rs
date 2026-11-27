//! NIP-46 remote-signer login, pairing, re-registration, inspection, and removal handlers.

use std::future::Future;
use std::io::{BufRead, IsTerminal, Write};
use std::pin::Pin;

use cgka_traits::TransportEndpoint;
use marmot_account::{AccountHome, AccountSummary, Nip46SessionRecord};
use marmot_app::{AppError, MarmotApp, MarmotAppRuntime, Nip46Error, Nip46Session, Nip46Status};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::args::{Nip46Command, Nip46PairArgs};
use crate::commands::account::{apply_global_relay_defaults, map_account_setup_error};
use crate::{
    CommandOutput, ImportBunkerUri, WnError, npub_for_account_id, relay_endpoints,
    relay_lists_json, resolve_account, terminal_safe_json_display, terminal_safe_text,
};

pub(crate) const DEFAULT_NIP46_CLIENT_NAME: &str = "White Noise CLI";

pub(crate) type PairingOfferCallback<'a> =
    Box<dyn FnMut(String) -> Pin<Box<dyn Future<Output = Result<(), WnError>> + Send>> + Send + 'a>;

pub(crate) struct Nip46LoginOptions {
    pub(crate) pair: Nip46PairArgs,
    pub(crate) relay: Option<String>,
    pub(crate) default_relays: Vec<String>,
    pub(crate) bootstrap_relays: Vec<String>,
    pub(crate) publish_missing_relay_lists: bool,
    pub(crate) daemon_default_account_relays: Vec<String>,
    pub(crate) daemon_discovery_relays: Vec<String>,
}

/// Returns true when `value` carries a NIP-46 URI scheme (`bunker://` or `nostrconnect://`).
pub(crate) fn is_nip46_uri(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("bunker://") || lower.starts_with("nostrconnect://")
}

pub(crate) fn is_bunker_uri(value: &str) -> bool {
    value.trim().to_ascii_lowercase().starts_with("bunker://")
}

/// Validate `--bunker-stdin` / `--nostrconnect` flags for `accounts nip46 login|register`.
pub(crate) fn validate_nip46_pair_flags(
    command: &'static str,
    pair: &Nip46PairArgs,
) -> Result<(), WnError> {
    if pair.bunker_stdin && pair.nostrconnect {
        return Err(WnError::ConflictingLoginInput { command });
    }
    if !pair.bunker_stdin && !pair.nostrconnect {
        return Err(WnError::MissingNip46Mode { command });
    }
    if pair.bunker_stdin && !pair.signer_relays.is_empty() {
        return Err(WnError::ConflictingLoginInput { command });
    }
    Ok(())
}

/// Review and confirm NIP-46 permissions on the client before connecting or forwarding to `wnd`.
///
/// Requires either explicit `--approve-permissions` or an affirmative interactive TTY answer
/// against the exact version and grant list returned by `Nip46Session::permissions()`.
pub(crate) fn obtain_nip46_permission_consent(
    approve_permissions: bool,
    stdin_consumed: bool,
) -> Result<(), WnError> {
    if approve_permissions {
        return Ok(());
    }
    let permissions = Nip46Session::permissions();
    if !std::io::stderr().is_terminal() {
        return Err(WnError::Nip46PermissionApprovalRequired {
            version: permissions.version,
            grants: permissions.grants,
        });
    }

    if !stdin_consumed && std::io::stdin().is_terminal() {
        let mut stderr = std::io::stderr().lock();
        let mut stdin = std::io::stdin().lock();
        return prompt_permission_consent(&mut stderr, &mut stdin, permissions);
    }

    #[cfg(unix)]
    if let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        let mut writer = tty.try_clone()?;
        let mut reader = std::io::BufReader::new(&mut tty);
        return prompt_permission_consent(&mut writer, &mut reader, permissions);
    }

    Err(WnError::Nip46PermissionApprovalRequired {
        version: permissions.version,
        grants: permissions.grants,
    })
}

fn prompt_permission_consent<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    permissions: marmot_app::Nip46Permissions,
) -> Result<(), WnError> {
    writeln!(
        writer,
        "NIP-46 remote signer permissions (version {}):",
        permissions.version
    )?;
    for grant in &permissions.grants {
        writeln!(writer, "  - {grant}")?;
    }
    write!(writer, "Approve these NIP-46 permissions? [y/N]: ")?;
    writer.flush()?;
    let mut response = String::new();
    let bytes = reader.read_line(&mut response)?;
    if bytes > 0 && matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }
    Err(WnError::Nip46PermissionApprovalRequired {
        version: permissions.version,
        grants: permissions.grants,
    })
}

pub(crate) fn write_pairing_offer_to_stderr(uri: &str) -> Result<(), WnError> {
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "Open or scan this NIP-46 nostrconnect URI in your remote signer:\n{}",
        terminal_safe_text(uri)
    )?;
    stderr.flush()?;
    Ok(())
}

fn stderr_pairing_offer_callback() -> PairingOfferCallback<'static> {
    Box::new(|uri| Box::pin(async move { write_pairing_offer_to_stderr(&uri) }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn nip46_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: Nip46Command,
    account_flag: Option<String>,
    relay: Option<String>,
    daemon_default_account_relays: Vec<String>,
    daemon_discovery_relays: Vec<String>,
    import_bunker: Option<ImportBunkerUri>,
) -> Result<CommandOutput, WnError> {
    if let Nip46Command::Status { account } = command {
        return nip46_status_command(account_home, None, account_flag, account).await;
    }
    let runtime = app.runtime();
    let result = nip46_command_with_runtime(
        account_home,
        app,
        &runtime,
        command,
        account_flag,
        relay,
        daemon_default_account_relays,
        daemon_discovery_relays,
        import_bunker,
        stderr_pairing_offer_callback(),
    )
    .await;
    runtime.shutdown().await;
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn nip46_command_with_runtime<'a>(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: Nip46Command,
    account_flag: Option<String>,
    relay: Option<String>,
    daemon_default_account_relays: Vec<String>,
    daemon_discovery_relays: Vec<String>,
    import_bunker: Option<ImportBunkerUri>,
    on_pairing_offer: PairingOfferCallback<'a>,
) -> Result<CommandOutput, WnError> {
    match command {
        Nip46Command::Login {
            pair,
            relay: login_relay,
            default_relays,
            bootstrap_relays,
            publish_missing_relay_lists,
        } => {
            nip46_login_with_runtime(
                account_home,
                app,
                runtime,
                Nip46LoginOptions {
                    pair,
                    relay: login_relay.or(relay),
                    default_relays,
                    bootstrap_relays,
                    publish_missing_relay_lists,
                    daemon_default_account_relays,
                    daemon_discovery_relays,
                },
                import_bunker,
                on_pairing_offer,
            )
            .await
        }
        Nip46Command::Register { account, pair } => {
            let mut fallback_relays = daemon_default_account_relays;
            if let Some(relay) = relay {
                fallback_relays.push(relay);
            }
            nip46_register_with_runtime(
                account_home,
                runtime,
                account_flag,
                account,
                pair,
                fallback_relays,
                import_bunker,
                on_pairing_offer,
            )
            .await
        }
        Nip46Command::Status { account } => {
            nip46_status_command(account_home, Some(runtime), account_flag, account).await
        }
        Nip46Command::Remove { account } => {
            nip46_remove_with_runtime(account_home, runtime, account_flag, account).await
        }
    }
}

pub(crate) async fn nip46_login_one_shot(
    account_home: &AccountHome,
    app: &MarmotApp,
    options: Nip46LoginOptions,
    import_bunker: Option<ImportBunkerUri>,
) -> Result<CommandOutput, WnError> {
    let runtime = app.runtime();
    let result = nip46_login_with_runtime(
        account_home,
        app,
        &runtime,
        options,
        import_bunker,
        stderr_pairing_offer_callback(),
    )
    .await;
    runtime.shutdown().await;
    result
}

pub(crate) async fn nip46_login_with_runtime<'a>(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    mut options: Nip46LoginOptions,
    import_bunker: Option<ImportBunkerUri>,
    on_pairing_offer: PairingOfferCallback<'a>,
) -> Result<CommandOutput, WnError> {
    validate_nip46_pair_flags("login", &options.pair)?;
    let (default_relays, bootstrap_relays) = resolve_nip46_login_relays(&mut options)?;
    let fallback_signer_relays = default_relays
        .iter()
        .chain(bootstrap_relays.iter())
        .map(|endpoint| endpoint.0.clone())
        .collect::<Vec<_>>();
    let session = connect_nip46_session(
        runtime,
        &options.pair,
        fallback_signer_relays,
        import_bunker,
        on_pairing_offer,
    )
    .await?;

    let account = match runtime
        .nip46_login(
            session.clone(),
            default_relays,
            bootstrap_relays,
            Vec::new(),
        )
        .await
    {
        Ok(account) => account,
        Err(err) => {
            session.cancel();
            return Err(map_account_setup_error(err));
        }
    };

    let relay_lists = app
        .directory()
        .account_relay_list_status_for_account_id(&account.account_id_hex)?;
    let npub = npub_for_account_id(&account.account_id_hex)?;
    let nip46 = nip46_session_summary_json(account_home, &account, Some(&session));
    Ok(CommandOutput {
        plain: format!(
            "logged in {} local-signing={} external-signing={}",
            npub, account.local_signing, account.external_signing
        ),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub,
            "local_signing": account.local_signing,
            "external_signing": account.external_signing,
            "signing_mode": signing_mode_str(&account),
            "relay_lists": relay_lists_json(relay_lists),
            "nip46": nip46,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn nip46_register_with_runtime<'a>(
    account_home: &AccountHome,
    runtime: &MarmotAppRuntime,
    account_flag: Option<String>,
    target_account: Option<String>,
    pair: Nip46PairArgs,
    fallback_signer_relays: Vec<String>,
    import_bunker: Option<ImportBunkerUri>,
    on_pairing_offer: PairingOfferCallback<'a>,
) -> Result<CommandOutput, WnError> {
    validate_nip46_pair_flags("accounts nip46 register", &pair)?;
    let account = resolve_account(account_home, target_account.or(account_flag))?;
    if !account.external_signing {
        return Err(WnError::Nip46RequiresExternalAccount(
            account.account_id_hex,
        ));
    }
    let session = connect_nip46_session(
        runtime,
        &pair,
        fallback_signer_relays,
        import_bunker,
        on_pairing_offer,
    )
    .await?;
    if let Err(err) = runtime
        .nip46_register(&account.account_id_hex, session.clone())
        .await
    {
        session.cancel();
        return Err(err.into());
    }
    let npub = npub_for_account_id(&account.account_id_hex)?;
    let nip46 = nip46_session_summary_json(account_home, &account, Some(&session));
    Ok(CommandOutput {
        plain: format!("registered NIP-46 remote signer for {npub}"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub,
            "local_signing": account.local_signing,
            "external_signing": account.external_signing,
            "signing_mode": signing_mode_str(&account),
            "registered": true,
            "nip46": nip46,
        }),
    })
}

pub(crate) async fn nip46_status_command(
    account_home: &AccountHome,
    runtime: Option<&MarmotAppRuntime>,
    account_flag: Option<String>,
    target_account: Option<String>,
) -> Result<CommandOutput, WnError> {
    let account = resolve_account(account_home, target_account.or(account_flag))?;
    let npub = npub_for_account_id(&account.account_id_hex)?;
    let live_session = match runtime {
        Some(runtime) if account.external_signing && !account.signed_out && !account.unlinked => {
            runtime.nip46_resume(&account.account_id_hex).await.ok()
        }
        _ => None,
    };
    let nip46 = nip46_session_summary_json(account_home, &account, live_session.as_ref());
    let json = json!({
        "account_id": account.account_id_hex,
        "npub": npub,
        "local_signing": account.local_signing,
        "external_signing": account.external_signing,
        "signing_mode": signing_mode_str(&account),
        "nip46": nip46,
    });
    Ok(CommandOutput {
        plain: terminal_safe_json_display(
            &serde_json::to_string_pretty(&json).expect("JSON response serialization cannot fail"),
        ),
        json,
    })
}

pub(crate) async fn nip46_remove_with_runtime(
    account_home: &AccountHome,
    runtime: &MarmotAppRuntime,
    account_flag: Option<String>,
    target_account: Option<String>,
) -> Result<CommandOutput, WnError> {
    let account = resolve_account(account_home, target_account.or(account_flag))?;
    if !account.external_signing {
        return Err(WnError::Nip46RequiresExternalAccount(
            account.account_id_hex,
        ));
    }
    runtime.nip46_remove(&account.account_id_hex).await?;
    let npub = npub_for_account_id(&account.account_id_hex)?;
    Ok(CommandOutput {
        plain: format!("removed NIP-46 session for {npub} (encrypted history preserved)"),
        json: json!({
            "account_id": account.account_id_hex,
            "npub": npub,
            "local_signing": account.local_signing,
            "external_signing": account.external_signing,
            "signing_mode": signing_mode_str(&account),
            "removed": true,
            "history_preserved": true,
        }),
    })
}

/// Cancels an unbound `Nip46Session` if the pairing future is dropped early (for example,
/// when a client disconnects or hits Ctrl-C while awaiting `pairing_offer` or `connect`).
struct CancelOnDrop(Option<Nip46Session>);

impl CancelOnDrop {
    fn session(&self) -> &Nip46Session {
        self.0
            .as_ref()
            .expect("CancelOnDrop session is present until disarmed")
    }

    fn disarm(mut self) -> Nip46Session {
        self.0
            .take()
            .expect("CancelOnDrop session is present until disarmed")
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(session) = self.0.take() {
            session.cancel();
        }
    }
}

async fn connect_nip46_session<'a>(
    runtime: &MarmotAppRuntime,
    pair: &Nip46PairArgs,
    fallback_signer_relays: Vec<String>,
    import_bunker: Option<ImportBunkerUri>,
    mut on_pairing_offer: PairingOfferCallback<'a>,
) -> Result<Nip46Session, WnError> {
    if !pair.approve_permissions {
        let permissions = Nip46Session::permissions();
        return Err(WnError::Nip46PermissionApprovalRequired {
            version: permissions.version,
            grants: permissions.grants,
        });
    }
    let client_name = pair
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_NIP46_CLIENT_NAME);
    let config_json =
        build_nip46_config_json(pair, fallback_signer_relays, client_name, import_bunker)?;
    let guard = CancelOnDrop(Some(runtime.nip46_new(&config_json)?));
    let reviewed = guard.session().review_permissions();
    guard
        .session()
        .approve_permissions(reviewed.version, reviewed.grants)
        .map_err(AppError::from)?;
    if pair.nostrconnect {
        let offer = guard
            .session()
            .pairing_offer()
            .await
            .map_err(AppError::from)?;
        on_pairing_offer(offer).await?;
    }
    guard
        .session()
        .connect_async()
        .await
        .map_err(AppError::from)?;
    Ok(guard.disarm())
}

fn build_nip46_config_json(
    pair: &Nip46PairArgs,
    fallback_signer_relays: Vec<String>,
    client_name: &str,
    import_bunker: Option<ImportBunkerUri>,
) -> Result<Zeroizing<String>, WnError> {
    if pair.bunker_stdin {
        let uri = import_bunker
            .ok_or(WnError::MissingBunkerStdin { command: "login" })?
            .into_inner();
        let config = serde_json::to_string(&json!({
            "uri": uri.as_str(),
            "name": client_name,
        }))?;
        return Ok(Zeroizing::new(config));
    }

    let raw_relays = if pair.signer_relays.is_empty() {
        fallback_signer_relays
    } else {
        pair.signer_relays.clone()
    };
    let relays = relay_endpoints(raw_relays)?
        .into_iter()
        .map(|endpoint| endpoint.0)
        .collect::<Vec<_>>();
    if relays.is_empty() {
        return Err(WnError::MissingNip46SignerRelays);
    }
    let config = serde_json::to_string(&json!({
        "relays": relays,
        "name": client_name,
    }))?;
    Ok(Zeroizing::new(config))
}

fn resolve_nip46_login_relays(
    options: &mut Nip46LoginOptions,
) -> Result<(Vec<TransportEndpoint>, Vec<TransportEndpoint>), WnError> {
    let explicit_relays =
        !options.default_relays.is_empty() || !options.bootstrap_relays.is_empty();
    let _ = apply_global_relay_defaults(
        &mut options.default_relays,
        &mut options.bootstrap_relays,
        options.relay.clone(),
    );
    if !explicit_relays && options.default_relays.is_empty() && options.bootstrap_relays.is_empty()
    {
        options.default_relays = options.daemon_default_account_relays.clone();
        options.bootstrap_relays = if options.daemon_discovery_relays.is_empty() {
            options.daemon_default_account_relays.clone()
        } else {
            options.daemon_discovery_relays.clone()
        };
    }
    if options.publish_missing_relay_lists && options.default_relays.is_empty() {
        if !options.daemon_default_account_relays.is_empty() {
            options.default_relays = options.daemon_default_account_relays.clone();
        } else if !options.bootstrap_relays.is_empty() {
            options.default_relays = options.bootstrap_relays.clone();
        }
    }
    if options.default_relays.is_empty() && options.bootstrap_relays.is_empty() {
        return Err(WnError::MissingRelay);
    }
    Ok((
        relay_endpoints(options.default_relays.clone())?,
        relay_endpoints(options.bootstrap_relays.clone())?,
    ))
}

pub(crate) fn signing_mode_str(account: &AccountSummary) -> &'static str {
    if account.local_signing {
        "local"
    } else if account.external_signing {
        "external"
    } else {
        "public"
    }
}

/// Non-secret NIP-46 summary for `accounts nip46 status` and `accounts status`.
///
/// Drops loaded secret communication keys immediately and never includes secrets,
/// pairing URIs, or `auth_url` challenges.
pub(crate) fn nip46_session_summary_json(
    account_home: &AccountHome,
    account: &AccountSummary,
    live_session: Option<&Nip46Session>,
) -> Value {
    if !account.external_signing {
        return Value::Null;
    }
    let persisted = match account_home.load_nip46_session(&account.label) {
        Ok(Some((_keys, record))) => Ok(Some(record)),
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    };
    match persisted {
        Ok(Some(record)) => nip46_record_json(record, live_session.map(Nip46Session::status)),
        Ok(None) => json!({
            "configured": false,
            "runtime_state": live_session.map(|s| s.status().state),
        }),
        Err(_) => json!({
            "configured": false,
            "storage_error": true,
        }),
    }
}

fn nip46_record_json(record: Nip46SessionRecord, status: Option<Nip46Status>) -> Value {
    let runtime = status.map(|status| {
        json!({
            "state": status.state,
            "last_error": status.last_error,
            "generation": status.generation,
            "auth_required": status.auth_url.is_some(),
        })
    });
    json!({
        "configured": true,
        "remote_signer_public_key": record.remote_signer_public_key,
        "client_public_key": record.client_public_key,
        "relays": record.relays,
        "client_name": record.name,
        "permission_version": record.permission_version,
        "permissions": record.permissions,
        "runtime": runtime,
    })
}

/// Returns true when the command is a `--nostrconnect` pairing command that streams its
/// pairing offer before awaiting remote connection.
pub(crate) fn is_nip46_nostrconnect_command(command: &crate::Command) -> bool {
    match command {
        crate::Command::Login { nip46, .. } => nip46.nostrconnect,
        crate::Command::Account {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { pair, .. } | Nip46Command::Register { pair, .. },
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { pair, .. } | Nip46Command::Register { pair, .. },
                },
        } => pair.nostrconnect,
        _ => false,
    }
}

/// Returns true when the command performs a NIP-46 login or register (either mode).
pub(crate) fn is_nip46_pairing_command(command: &crate::Command) -> bool {
    match command {
        crate::Command::Login { nip46, .. } => nip46.bunker_stdin || nip46.nostrconnect,
        crate::Command::Account {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { .. } | Nip46Command::Register { .. },
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { .. } | Nip46Command::Register { .. },
                },
        } => true,
        _ => false,
    }
}

pub(crate) fn nip46_pair_args_mut(command: &mut crate::Command) -> Option<&mut Nip46PairArgs> {
    match command {
        crate::Command::Login { nip46, .. } if nip46.bunker_stdin || nip46.nostrconnect => {
            Some(nip46)
        }
        crate::Command::Account {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { pair, .. } | Nip46Command::Register { pair, .. },
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Nip46 {
                    command: Nip46Command::Login { pair, .. } | Nip46Command::Register { pair, .. },
                },
        } => Some(pair),
        _ => None,
    }
}

pub(crate) fn nip46_error_is_missing_session(err: &AppError) -> bool {
    matches!(err, AppError::Nip46(Nip46Error::Unavailable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn interactive_permission_prompt_requires_explicit_yes() {
        let perms = Nip46Session::permissions();
        let mut out = Vec::new();
        let mut yes = Cursor::new(b"y\n".as_slice());
        prompt_permission_consent(&mut out, &mut yes, perms.clone())
            .expect("explicit y approves permissions");
        let rendered = String::from_utf8(out).expect("utf8");
        assert!(rendered.contains("sign_event:450"));
        assert!(rendered.contains("nip44_decrypt"));

        for input in [b"\n".as_slice(), b"n\n".as_slice(), b"maybe\n".as_slice()] {
            let mut out = Vec::new();
            let mut reader = Cursor::new(input);
            let err = prompt_permission_consent(&mut out, &mut reader, perms.clone())
                .expect_err("non-yes must reject");
            assert!(matches!(
                err,
                WnError::Nip46PermissionApprovalRequired { .. }
            ));
        }
    }

    #[test]
    fn nip46_uri_detection_recognizes_bunker_and_nostrconnect_case_insensitively() {
        assert!(is_nip46_uri("bunker://abcd?relay=wss://r&secret=xyz"));
        assert!(is_nip46_uri("  BUNKER://abcd  "));
        assert!(is_nip46_uri("nostrconnect://abcd?relay=wss://r&secret=xyz"));
        assert!(!is_nip46_uri("npub1example"));
        assert!(!is_nip46_uri("nsec1example"));
    }

    #[test]
    fn nip46_record_json_never_exposes_auth_url_or_secret_keys() {
        let record = Nip46SessionRecord {
            version: 1,
            user_public_key: "11".repeat(32),
            remote_signer_public_key: "22".repeat(32),
            client_public_key: "33".repeat(32),
            relays: vec!["wss://relay.example".to_owned()],
            name: "White Noise CLI".to_owned(),
            permission_version: 1,
            permissions: vec!["sign_event:450".to_owned()],
        };
        let status = Nip46Status {
            state: marmot_app::Nip46State::Approval,
            last_error: None,
            auth_url: Some("https://signer.example/secret-auth-token".to_owned()),
            request_id: Some("req-1".to_owned()),
            generation: 2,
        };
        let rendered = nip46_record_json(record, Some(status));
        let text = rendered.to_string();
        assert!(!text.contains("secret-auth-token"));
        assert_eq!(rendered["runtime"]["auth_required"], true);
        assert_eq!(rendered["configured"], true);
    }
}
