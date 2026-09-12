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

/// Matches the currently locked Bech32/Bech32m code-length ceiling
/// (`bech32` 0.11.1), not a universal NIP-19 protocol limit.
const MAX_NPROFILE_REFERENCE_BYTES: usize = 1023;

/// Normalize a public identity reference into a canonical hex account id.
///
/// Accepts hex, `npub`, one lowercase `nostr:npub` prefix, bare `nprofile`,
/// and one lowercase `nostr:nprofile` prefix. Existing hex/npub/NIP-21
/// behavior stays on [`PublicKey::parse`]; nprofile is a fallback that
/// returns only `profile.public_key` hex and discards every relay hint.
/// Duplicate type-0 TLV entries keep the first 32-byte key (SDK first-wins).
///
/// The fallback runs only after `PublicKey::parse` fails. It strips at most
/// one exact lowercase `nostr:` prefix and then rejects encoded tokens
/// longer than 1023 UTF-8 bytes, counting the
/// HRP, separator, and checksum but excluding that one prefix. Decorated
/// wrappers such as `marmot://profile/...` are not stripped here; FFI
/// canonicalizes those before calling this helper. A valid 1023-byte token
/// wrapped in `nostr:` therefore still decodes even though the complete
/// wrapper is longer.
///
/// This helper does not trim whitespace, allocate, or normalize case. The
/// legacy NIP-21 parser may still accept a colon-suffixed `nostr:<npub>:`
/// form before the fallback runs. Failures map to
/// [`AppError::InvalidPublicKey`] without echoing the input. The local
/// token limit makes the fallback budget explicit; it does not bound
/// `PublicKey::parse`, FFI allocation, or C NUL scanning.
pub fn account_id_hex_from_ref(reference: &str) -> Result<String, AppError> {
    if let Ok(pubkey) = PublicKey::parse(reference) {
        return Ok(pubkey.to_hex());
    }
    let profile_ref = nprofile_fallback_token(reference)?;
    Nip19Profile::from_bech32(profile_ref)
        .map(|profile| profile.public_key.to_hex())
        .map_err(|_| AppError::InvalidPublicKey)
}

fn nprofile_fallback_token(reference: &str) -> Result<&str, AppError> {
    let profile_ref = reference.strip_prefix("nostr:").unwrap_or(reference);
    if profile_ref.len() > MAX_NPROFILE_REFERENCE_BYTES {
        return Err(AppError::InvalidPublicKey);
    }
    Ok(profile_ref)
}

pub(crate) fn npub_for_account_id_lossy(account_id_hex: &str) -> String {
    npub_for_account_id(account_id_hex).unwrap_or_else(|_| account_id_hex.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_NPROFILE_REFERENCE_BYTES, account_id_hex_from_ref, nprofile_fallback_token,
        nprofile_for_account_id, npub_for_account_id, parse_account_id_hex,
    };
    use crate::AppError;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/identity_reference_vectors.rs"
    ));

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

        let no_relay = nprofile_for_account_id(ACCOUNT_ID, &[]).unwrap();
        assert_eq!(no_relay, NO_RELAY_NPROFILE);
        let other_relays =
            nprofile_for_account_id(ACCOUNT_ID, &["wss://relay.example.invalid".to_owned()])
                .unwrap();
        assert_eq!(other_relays, OTHER_RELAY_NPROFILE);
        assert_ne!(other_relays, BOOTSTRAP_NPROFILE);
    }

    #[test]
    fn account_id_hex_from_ref_matches_shared_corpus() {
        for case in cases() {
            match case.app_account_id_hex {
                Some(expected) => {
                    assert_eq!(
                        account_id_hex_from_ref(&case.reference)
                            .unwrap_or_else(|_| panic!("case {} should decode", case.name)),
                        expected,
                        "case {}",
                        case.name
                    );
                }
                None => {
                    assert!(
                        matches!(
                            account_id_hex_from_ref(&case.reference),
                            Err(AppError::InvalidPublicKey)
                        ),
                        "case {} should reject",
                        case.name
                    );
                }
            }
        }
    }

    #[test]
    fn nprofile_fallback_token_rejects_oversized_tokens_before_sdk_decode() {
        let accepted = "q".repeat(MAX_NPROFILE_REFERENCE_BYTES);
        assert_eq!(
            nprofile_fallback_token(&accepted).expect("1023-byte token stays eligible"),
            accepted.as_str()
        );
        let wrapped = format!("nostr:{accepted}");
        assert_eq!(
            nprofile_fallback_token(&wrapped).expect("prefix is excluded from the budget"),
            accepted.as_str()
        );

        let oversized = "q".repeat(MAX_NPROFILE_REFERENCE_BYTES + 1);
        assert!(
            matches!(
                nprofile_fallback_token(&oversized),
                Err(AppError::InvalidPublicKey)
            ),
            "1024-byte token must not reach Nip19Profile::from_bech32"
        );
        assert!(
            matches!(
                nprofile_fallback_token(&format!("nostr:{oversized}")),
                Err(AppError::InvalidPublicKey)
            ),
            "prefixed oversized token must not reach Nip19Profile::from_bech32"
        );
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
