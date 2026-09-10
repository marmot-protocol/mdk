use cgka_traits::MemberId;
use nostr::FromBech32;
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

/// Normalize a public identity reference into a canonical hex account id.
///
/// Accepts hex, `npub`, one lowercase `nostr:npub` prefix, bare `nprofile`,
/// and one lowercase `nostr:nprofile` prefix. Existing hex/npub/NIP-21
/// behavior stays on [`PublicKey::parse`]; nprofile is a fallback that
/// returns only `profile.public_key` hex and discards every relay hint.
/// This helper does not trim whitespace. Failures map to
/// [`AppError::InvalidPublicKey`] without echoing the input.
pub fn account_id_hex_from_ref(reference: &str) -> Result<String, AppError> {
    if let Ok(pubkey) = PublicKey::parse(reference) {
        return Ok(pubkey.to_hex());
    }
    let profile_ref = reference.strip_prefix("nostr:").unwrap_or(reference);
    Nip19Profile::from_bech32(profile_ref)
        .map(|profile| profile.public_key.to_hex())
        .map_err(|_| AppError::InvalidPublicKey)
}

pub(crate) fn npub_for_account_id_lossy(account_id_hex: &str) -> String {
    npub_for_account_id(account_id_hex).unwrap_or_else(|_| account_id_hex.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        account_id_hex_from_ref, nprofile_for_account_id, npub_for_account_id, parse_account_id_hex,
    };
    use crate::AppError;
    use nostr::nips::nip01::Coordinate;
    use nostr::nips::nip19::{Nip19Coordinate, Nip19Event};
    use nostr::{EventId, Kind, SecretKey, ToBech32};
    use nostr_sdk::prelude::PublicKey;

    const ACCOUNT_ID: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    const NPUB: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";
    const BOOTSTRAP_NPROFILE: &str = "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqpremhxue69uhhyetvv9uju\
         et49emks6t5v4hx76tnv5hxx6rpwsq3uamnwvaz7tmjv4kxz7fww4ejuamgd96x2mn0d9ek2tnrdpshggcu28s";
    const NO_RELAY_NPROFILE: &str =
        "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dq7r0nz9";
    const UNKNOWN_TLV_NPROFILE: &str =
        "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0drrq3skycmyxne9kf";
    const INVALID_RELAY_NPROFILE: &str =
        "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqpp9hx7apqvys82unvuca0cf";
    const DUPLICATE_TYPE0_NPROFILE: &str = "nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dqqyzamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamkq4uk7z";
    const MISSING_TYPE0_NPROFILE: &str = "nprofile1qy2hwumn8ghj7etcv9khqmr99e5kuanpd35kghsdudn";
    const SHORT_TYPE0_NPROFILE: &str = "nprofile1qqg25n7gve04d9hr8km7rftjuwc028ngcqe";
    const TRUNCATED_HEADER_NPROFILE: &str = "nprofile1qqqsnhxh";
    const TRUNCATED_VALUE_NPROFILE: &str = "nprofile1qqs25n7gve04d9hrdfl42d";
    const WRONG_HRP_NOTE: &str =
        "note1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dq4ueyyt";

    fn assert_account_id(reference: &str) {
        assert_eq!(
            account_id_hex_from_ref(reference).expect("valid identity reference"),
            ACCOUNT_ID
        );
    }

    fn assert_invalid(reference: &str) {
        assert!(
            matches!(
                account_id_hex_from_ref(reference),
                Err(AppError::InvalidPublicKey)
            ),
            "expected InvalidPublicKey"
        );
    }

    #[test]
    fn npub_and_nprofile_match_bootstrap_vectors() {
        let npub = npub_for_account_id(ACCOUNT_ID).unwrap();
        assert_eq!(npub, NPUB);

        let nprofile = nprofile_for_account_id(
            ACCOUNT_ID,
            &[
                "wss://relay.eu.whitenoise.chat".to_owned(),
                "wss://relay.us.whitenoise.chat".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(nprofile, BOOTSTRAP_NPROFILE);
    }

    #[test]
    fn account_id_hex_from_ref_accepts_hex_npub_and_nprofile_spellings() {
        let no_relay = nprofile_for_account_id(ACCOUNT_ID, &[]).unwrap();
        assert_eq!(no_relay, NO_RELAY_NPROFILE);
        let other_relays =
            nprofile_for_account_id(ACCOUNT_ID, &["wss://relay.example.invalid".to_owned()])
                .unwrap();
        assert_ne!(other_relays, BOOTSTRAP_NPROFILE);

        for reference in [
            ACCOUNT_ID,
            &ACCOUNT_ID.to_ascii_uppercase(),
            NPUB,
            &format!("nostr:{NPUB}"),
            BOOTSTRAP_NPROFILE,
            &format!("nostr:{BOOTSTRAP_NPROFILE}"),
            NO_RELAY_NPROFILE,
            &format!("nostr:{NO_RELAY_NPROFILE}"),
            &other_relays,
            UNKNOWN_TLV_NPROFILE,
            INVALID_RELAY_NPROFILE,
            DUPLICATE_TYPE0_NPROFILE,
        ] {
            assert_account_id(reference);
        }
    }

    #[test]
    fn account_id_hex_from_ref_keeps_untrimmed_whitespace_behavior() {
        assert_invalid(&format!(" {ACCOUNT_ID}"));
        assert_invalid(&format!("{NPUB} "));
        assert_invalid(&format!(" {BOOTSTRAP_NPROFILE}"));
    }

    #[test]
    fn account_id_hex_from_ref_rejects_checksum_damage_and_wrong_hrp() {
        let mut damaged_npub = NPUB.to_owned();
        damaged_npub.replace_range(damaged_npub.len() - 1.., "x");
        assert_ne!(damaged_npub, NPUB);
        assert_invalid(&damaged_npub);

        let mut damaged_nprofile = NO_RELAY_NPROFILE.to_owned();
        damaged_nprofile.replace_range(damaged_nprofile.len() - 1.., "x");
        assert_ne!(damaged_nprofile, NO_RELAY_NPROFILE);
        assert_invalid(&damaged_nprofile);

        assert_invalid(WRONG_HRP_NOTE);
        assert_invalid(
            "NOSTR:nprofile1qqs25n7gve04d9hr8km7rftjuwc0tv7kzkphkrek9h93eqrgkzvv0dq7r0nz9",
        );
        assert_invalid(&format!("nostr:nostr:{NO_RELAY_NPROFILE}"));
    }

    #[test]
    fn account_id_hex_from_ref_rejects_event_and_secret_hrps() {
        let public_key = PublicKey::parse(ACCOUNT_ID).unwrap();
        let event_id = EventId::from_slice(&[0x22; 32]).unwrap();
        let note = event_id.to_bech32().unwrap();
        let nevent = Nip19Event::new(event_id)
            .author(public_key)
            .to_bech32()
            .unwrap();
        let naddr = Nip19Coordinate::new(Coordinate::new(Kind::Metadata, public_key), [])
            .to_bech32()
            .unwrap();
        let nsec = SecretKey::from_slice(&[0x11; 32])
            .unwrap()
            .to_bech32()
            .unwrap();

        assert_invalid(&note);
        assert_invalid(&nevent);
        assert_invalid(&naddr);
        assert_invalid(&nsec);
    }

    #[test]
    fn account_id_hex_from_ref_rejects_truncated_and_missing_type0() {
        assert_invalid(MISSING_TYPE0_NPROFILE);
        assert_invalid(SHORT_TYPE0_NPROFILE);
        assert_invalid(TRUNCATED_HEADER_NPROFILE);
        assert_invalid(TRUNCATED_VALUE_NPROFILE);
    }

    #[test]
    fn parse_account_id_hex_does_not_gain_nprofile() {
        assert_eq!(parse_account_id_hex(ACCOUNT_ID).unwrap(), ACCOUNT_ID);
        assert_eq!(parse_account_id_hex(NPUB).unwrap(), ACCOUNT_ID);
        assert!(matches!(
            parse_account_id_hex(NO_RELAY_NPROFILE),
            Err(AppError::InvalidPublicKey)
        ));
    }
}
