use cgka_traits::MemberId;

use crate::AppError;

// The Nostr account-id helpers moved to the directory (step 3 of
// docs/marmot-architecture/review/brief-directory.md); re-exported so callers
// keep their paths.
/// Convert a hex Nostr public key (account id) into its `npub...` bech32 form.
/// Public so embedders (FFI/UI) can render npubs instead of raw hex.
pub fn npub_for_account_id(account_id_hex: &str) -> Result<String, AppError> {
    Ok(crate::directory::ids::npub_for_account_id(account_id_hex)?)
}

/// Validate relay URL strings before encoding them into invite URIs.
pub fn validate_relay_urls(relays: &[String]) -> Result<(), AppError> {
    Ok(crate::directory::ids::validate_relay_urls(relays)?)
}

/// Encode a hex account id and relay hints as an `nprofile1…` invite URI.
pub fn nprofile_for_account_id(
    account_id_hex: &str,
    relays: &[String],
) -> Result<String, AppError> {
    Ok(crate::directory::ids::nprofile_for_account_id(
        account_id_hex,
        relays,
    )?)
}

/// Normalize a public identity reference (hex, `npub`, `nostr:npub`, `nprofile`
/// or `nostr:nprofile`) into a canonical hex account id. Failures return
/// [`AppError::InvalidPublicKey`] without echoing the input; see
/// [`crate::directory::ids::account_id_hex_from_ref`].
pub fn account_id_hex_from_ref(reference: &str) -> Result<String, AppError> {
    Ok(crate::directory::ids::account_id_hex_from_ref(reference)?)
}
pub(crate) use crate::directory::ids::{normalize_account_ids, parse_account_id_hex};

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
