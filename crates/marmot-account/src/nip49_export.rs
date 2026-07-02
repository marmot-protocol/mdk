//! NIP-49 encrypted private-key export helpers.
//!
//! This module owns the account-home policy around `ncryptsec1...` backups:
//! fixed mobile-friendly scrypt cost, non-empty passphrases, and persisted
//! key-security metadata. The NIP-49 crypto and wire layout are delegated to the
//! upstream `nostr` implementation so this crate does not carry a second
//! hand-rolled copy of sensitive encryption code.

use nostr::ToBech32;
use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};

use crate::error::{AccountHomeError, AccountHomeResult};

pub(crate) const NIP49_DEFAULT_LOG_N: u8 = 18;

pub(crate) fn export_ncryptsec(
    secret_key: &nostr::SecretKey,
    passphrase: &str,
    key_security_byte: u8,
) -> AccountHomeResult<String> {
    export_ncryptsec_with_log_n(
        secret_key,
        passphrase,
        NIP49_DEFAULT_LOG_N,
        key_security_byte,
    )
}

fn export_ncryptsec_with_log_n(
    secret_key: &nostr::SecretKey,
    passphrase: &str,
    log_n: u8,
    key_security_byte: u8,
) -> AccountHomeResult<String> {
    if passphrase.is_empty() {
        return Err(AccountHomeError::EmptyPassphrase);
    }

    let key_security = key_security_from_byte(key_security_byte)?;
    let encrypted = EncryptedSecretKey::new(secret_key, passphrase, log_n, key_security)
        .map_err(encrypted_export_error)?;
    encrypted.to_bech32().map_err(encrypted_export_error)
}

fn key_security_from_byte(value: u8) -> AccountHomeResult<KeySecurity> {
    KeySecurity::try_from(value).map_err(|err| {
        AccountHomeError::EncryptedSecretExport(format!(
            "unsupported NIP-49 key security byte: {value:#04x}: {err}"
        ))
    })
}

fn encrypted_export_error(error: impl std::fmt::Display) -> AccountHomeError {
    AccountHomeError::EncryptedSecretExport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip19::FromBech32;

    #[test]
    fn exported_material_decrypts_with_nostr_nip49_reference() {
        let secret_key = nostr::SecretKey::from_hex(
            "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
        )
        .unwrap();

        let ncryptsec = export_ncryptsec_with_log_n(&secret_key, "nostr", 16, 0x01).unwrap();

        assert!(ncryptsec.starts_with("ncryptsec1"));
        let encrypted = EncryptedSecretKey::from_bech32(&ncryptsec).unwrap();
        assert_eq!(encrypted.log_n(), 16);
        assert_eq!(encrypted.key_security(), KeySecurity::Medium);
        assert_eq!(encrypted.decrypt("nostr").unwrap(), secret_key);
    }

    #[test]
    fn export_normalizes_passphrase_nfkc() {
        let secret_key = nostr::SecretKey::from_hex(
            "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
        )
        .unwrap();

        let ncryptsec =
            export_ncryptsec_with_log_n(&secret_key, "ｔｅｓｔ１２３", 12, 0x02).unwrap();

        let encrypted = EncryptedSecretKey::from_bech32(&ncryptsec).unwrap();
        assert_eq!(encrypted.key_security(), KeySecurity::Unknown);
        assert_eq!(encrypted.decrypt("test123").unwrap(), secret_key);
    }

    #[test]
    fn export_rejects_empty_passphrase() {
        let secret_key = nostr::SecretKey::from_hex(
            "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
        )
        .unwrap();

        assert!(matches!(
            export_ncryptsec_with_log_n(&secret_key, "", 12, 0x02),
            Err(AccountHomeError::EmptyPassphrase)
        ));
    }

    #[test]
    fn export_reports_corrupt_key_security_byte() {
        let secret_key = nostr::SecretKey::from_hex(
            "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
        )
        .unwrap();

        let err = export_ncryptsec_with_log_n(&secret_key, "test123", 12, 0x03).unwrap_err();
        assert!(matches!(
            err,
            AccountHomeError::EncryptedSecretExport(message)
                if message.contains("unsupported NIP-49 key security byte: 0x03")
        ));
    }
}
