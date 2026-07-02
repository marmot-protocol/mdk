use cgka_traits::MemberId;
use nostr::ToBech32;
use nostr::nips::nip19::Nip19Profile;
use nostr::prelude::RelayUrl;
use nostr_sdk::prelude::PublicKey;

use crate::AppError;

pub(crate) fn parse_account_id_hex(value: &str) -> Result<String, AppError> {
    PublicKey::parse(value)
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| AppError::InvalidPublicKey)
}

pub(crate) fn normalize_group_id_hex_app(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    let bytes = hex::decode(&normalized)?;
    if bytes.is_empty() {
        return Err(AppError::UnknownGroup(value.to_owned()));
    }
    Ok(normalized)
}

pub(crate) fn admin_pubkey_from_account_id_hex(account_id_hex: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(parse_account_id_hex(account_id_hex)?)?;
    bytes.try_into().map_err(|_| AppError::InvalidPublicKey)
}

pub(crate) fn admin_pubkey_from_member_id(member_id: &MemberId) -> Result<[u8; 32], AppError> {
    member_id
        .as_slice()
        .try_into()
        .map_err(|_| AppError::InvalidPublicKey)
}

pub(crate) fn normalize_account_ids(values: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut values = values
        .into_iter()
        .map(|value| parse_account_id_hex(&value))
        .collect::<Result<Vec<_>, _>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

/// Convert a hex Nostr public key (account id) into its `npub...` bech32 form.
/// Public so embedders (FFI/UI) can render npubs instead of raw hex.
pub fn npub_for_account_id(account_id_hex: &str) -> Result<String, AppError> {
    PublicKey::parse(account_id_hex)
        .map_err(|_| AppError::InvalidPublicKey)?
        .to_bech32()
        .map_err(|_| AppError::InvalidPublicKey)
}

fn parse_relay_urls(relays: &[String]) -> Result<Vec<RelayUrl>, AppError> {
    relays
        .iter()
        .map(|relay| {
            RelayUrl::parse(relay).map_err(|_| AppError::InvalidNostrRouting(relay.clone()))
        })
        .collect()
}

/// Validate relay URL strings before encoding them into invite URIs.
pub fn validate_relay_urls(relays: &[String]) -> Result<(), AppError> {
    parse_relay_urls(relays).map(|_| ())
}

/// Encode a hex account id and relay hints as an `nprofile1…` invite URI.
pub fn nprofile_for_account_id(
    account_id_hex: &str,
    relays: &[String],
) -> Result<String, AppError> {
    let public_key = PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
    let relay_urls = parse_relay_urls(relays)?;
    Nip19Profile::new(public_key, relay_urls)
        .to_bech32()
        .map_err(|_| AppError::InvalidPublicKey)
}

/// Normalize any public-key reference (npub bech32 or hex) into canonical
/// hex account id. Public so embedders can resolve scanned/typed npubs.
pub fn account_id_hex_from_ref(reference: &str) -> Result<String, AppError> {
    Ok(PublicKey::parse(reference)
        .map_err(|_| AppError::InvalidPublicKey)?
        .to_hex())
}

pub(crate) fn npub_for_account_id_lossy(account_id_hex: &str) -> String {
    npub_for_account_id(account_id_hex).unwrap_or_else(|_| account_id_hex.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{nprofile_for_account_id, npub_for_account_id};

    const ACCOUNT_ID: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";

    #[test]
    fn npub_and_nprofile_match_bootstrap_vectors() {
        let npub = npub_for_account_id(ACCOUNT_ID).unwrap();
        assert_eq!(
            npub,
            "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"
        );

        let nprofile = nprofile_for_account_id(
            ACCOUNT_ID,
            &[
                "wss://relay.eu.whitenoise.chat".to_owned(),
                "wss://relay.us.whitenoise.chat".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            nprofile,
            "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqpremhxue69uhhyetvv9uju\
             et49emks6t5v4hx76tnv5hxx6rpwsq3uamnwvaz7tmjv4kxz7fww4ejuamgd96x2mn0d9ek2tnrdpshggcu28s"
        );
    }
}
