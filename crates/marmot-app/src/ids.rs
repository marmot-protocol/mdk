use cgka_traits::MemberId;

use crate::AppError;

// The Nostr account-id helpers moved to the directory (step 3 of
// docs/marmot-architecture/review/brief-directory.md); re-exported so callers
// keep their paths.
pub use crate::directory::ids::{
    account_id_hex_from_ref, nprofile_for_account_id, npub_for_account_id, validate_relay_urls,
};
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
