//! `profile` command namespace handlers.

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use marmot_app::{AccountRelayListBootstrap, MarmotApp, MarmotAppRuntime};
use serde_json::json;

use crate::{
    CommandOutput, DmError, ProfileCommand, ensure_local_signing, npub_for_account_id,
    resolve_account, unix_now_seconds, validate_relay_url,
};

pub(crate) async fn profile_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: ProfileCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    profile_command_with_runtime(account_home, app, &runtime, command, account_flag, relay).await
}

pub(crate) async fn profile_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: ProfileCommand,
    account_flag: Option<String>,
    relay: Option<String>,
) -> Result<CommandOutput, DmError> {
    let account = resolve_account(account_home, account_flag)?;
    ensure_local_signing(&account)?;
    match command {
        ProfileCommand::Show => {
            let entry = app.directory_entry_for_account_id(&account.account_id_hex)?;
            Ok(CommandOutput {
                plain: serde_json::to_string_pretty(&entry)
                    .expect("JSON response serialization cannot fail"),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "profile": entry.and_then(|entry| entry.profile),
                }),
            })
        }
        ProfileCommand::Update {
            name,
            display_name,
            about,
            picture,
            nip05,
            lud16,
        } => {
            // A flag-per-field update is partial by intent: the user names the
            // fields they want to change and expects the rest of their kind:0
            // profile to survive. kind:0 is a *replaceable* event, though, so a
            // naive publish of just the passed flags overwrites the whole
            // profile and silently wipes every unset field. Reject the
            // no-flags call outright (it would publish an empty {} and erase
            // everything), then fetch the current published profile, overlay
            // only the provided fields, and publish the merged result. This
            // mirrors the relays-add replaceable-list flow (fetch current,
            // merge, refuse to clobber when the relay has no current event).
            if name.is_none()
                && display_name.is_none()
                && about.is_none()
                && picture.is_none()
                && nip05.is_none()
                && lud16.is_none()
            {
                return Err(DmError::EmptyProfileUpdate);
            }
            let relay = relay.ok_or(DmError::MissingRelay)?;
            let endpoint = TransportEndpoint(validate_relay_url(&relay)?);
            let mut profile = app
                .fetch_current_user_profile_for_account_id(
                    &account.account_id_hex,
                    vec![endpoint.clone()],
                )
                .await?
                .ok_or_else(|| DmError::ProfileUpdateInconclusive {
                    account_id: account.account_id_hex.clone(),
                    source_relays: vec![endpoint.0.clone()],
                })?;
            if let Some(name) = name {
                profile.name = Some(name);
            }
            if let Some(display_name) = display_name {
                profile.display_name = Some(display_name);
            }
            if let Some(about) = about {
                profile.about = Some(about);
            }
            if let Some(picture) = picture {
                profile.picture = Some(picture);
            }
            if let Some(nip05) = nip05 {
                profile.nip05 = Some(nip05);
            }
            if let Some(lud16) = lud16 {
                profile.lud16 = Some(lud16);
            }
            profile.created_at = unix_now_seconds();
            profile.source_relays = Vec::new();
            runtime
                .publish_user_profile(
                    &account.label,
                    profile.clone(),
                    AccountRelayListBootstrap::new(vec![endpoint.clone()], vec![endpoint]),
                )
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "updated profile {}",
                    npub_for_account_id(&account.account_id_hex)?
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex)?,
                    "profile": profile,
                }),
            })
        }
    }
}
