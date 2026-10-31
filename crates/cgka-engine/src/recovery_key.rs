//! Recovery keys (mdk#2628 4.4a, D34 item 2): the key pair an account's
//! backups are sealed to, derived from the 128 bits of entropy its 12
//! recovery words carry.
//!
//! The derivation is fixed and independent of any group, because a device
//! that restores may hold none:
//!
//! ```text
//! prk = HKDF-Extract(SHA-256, salt = "marmot recovery key v1", ikm = entropy)
//! ikm = HKDF-Expand(SHA-256, prk, info = "marmot recovery key pair", 32)
//! key pair = DeriveKeyPair(ikm), DHKEM(X25519, HKDF-SHA256)
//! ```
//!
//! That is the KEM of ciphersuite `0x0001`, whatever ciphersuite the
//! account's device group uses. Devices keep only the public half, in the
//! roster's account entry; the private half exists only while the user's
//! words are in hand.
//!
//! Sealing is MLS's `EncryptWithLabel` (RFC 9420, section 5.1.3) with the
//! label "Marmot Backup" and the caller's context, under `0x0001`'s HPKE, as
//! history keys seal under "Marmot History" ([`crate::history_key`]). What the
//! context binds is the caller's to decide. A bad recipient key, or a value
//! that does not decode exactly or open, gives `None`, never an error.
//!
//! A device must not tell its user that words are not in use while a branch
//! that branch selection can still pick would make their key the account's;
//! [`Engine::recovery_key_selectable`] answers that from what the engine
//! keeps until the rewind horizon.

use crate::app_components::account_entry_of_group;
use crate::engine::Engine;
use crate::history_key::{open_with_label, seal_with_label};
use crate::openmls_projection::{
    retained_anchor_epoch_from_snapshot_name, with_retained_anchor_group,
};
use crate::snapshot_guard::RewindSite;
use cgka_traits::engine::SendIntent;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HashType, HpkeKeyPair};

/// The entropy the 12 recovery words carry: 128 bits.
pub const RECOVERY_ENTROPY_LEN: usize = 16;

/// Recovery keys use ciphersuite `0x0001`'s KEM and HPKE, whatever the
/// device group's ciphersuite.
const RECOVERY_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const DERIVE_SALT: &[u8] = b"marmot recovery key v1";
const DERIVE_INFO: &[u8] = b"marmot recovery key pair";
/// `EncryptWithLabel`'s label for "Marmot Backup" (RFC 9420, section 5.1.3).
const ENCRYPT_LABEL: &[u8] = b"MLS 1.0 Marmot Backup";

/// The recovery key pair `entropy` derives.
pub fn derive_recovery_key_pair<C: OpenMlsCrypto>(
    crypto: &C,
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
) -> Result<HpkeKeyPair, EngineError> {
    let prk = crypto
        .hkdf_extract(HashType::Sha2_256, DERIVE_SALT, entropy)
        .map_err(|e| EngineError::Backend(format!("recovery key extract: {e:?}")))?;
    let ikm = crypto
        .hkdf_expand(
            HashType::Sha2_256,
            prk.as_slice(),
            DERIVE_INFO,
            RECOVERY_CIPHERSUITE.hash_length(),
        )
        .map_err(|e| EngineError::Backend(format!("recovery key expand: {e:?}")))?;
    crypto
        .derive_hpke_keypair(RECOVERY_CIPHERSUITE.hpke_config(), ikm.as_slice())
        .map_err(|e| EngineError::Backend(format!("recovery key derivation: {e:?}")))
}

/// `plaintext` sealed to `recovery_public_key` for `context`, or `None` when
/// the key is not an X25519 public key.
pub fn seal_to_recovery_key<C: OpenMlsCrypto>(
    crypto: &C,
    recovery_public_key: &[u8],
    context: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    seal_with_label(
        crypto,
        RECOVERY_CIPHERSUITE,
        ENCRYPT_LABEL,
        recovery_public_key,
        context,
        plaintext,
    )
}

/// `sealed` opened with the recovery key `entropy` derives, for `context`;
/// `None` when it does not decode exactly or does not open: it was sealed to
/// other words, for another context, or altered.
pub fn open_with_recovery_key<C: OpenMlsCrypto>(
    crypto: &C,
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
    context: &[u8],
    sealed: &[u8],
) -> Result<Option<Vec<u8>>, EngineError> {
    let pair = derive_recovery_key_pair(crypto, entropy)?;
    Ok(open_with_label(
        crypto,
        RECOVERY_CIPHERSUITE,
        ENCRYPT_LABEL,
        &pair.private,
        context,
        sealed,
    ))
}

impl<S: StorageProvider> Engine<S> {
    /// The public half of the recovery key `entropy` derives. Nothing is
    /// stored.
    pub fn recovery_public_key(
        &self,
        entropy: &[u8; RECOVERY_ENTROPY_LEN],
    ) -> Result<Vec<u8>, EngineError> {
        Ok(derive_recovery_key_pair(&self.crypto, entropy)?.public)
    }

    /// See [`seal_to_recovery_key`].
    pub fn seal_to_recovery_key(
        &self,
        recovery_public_key: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        seal_to_recovery_key(&self.crypto, recovery_public_key, context, plaintext)
    }

    /// See [`open_with_recovery_key`].
    pub fn open_with_recovery_key(
        &self,
        entropy: &[u8; RECOVERY_ENTROPY_LEN],
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EngineError> {
        open_with_recovery_key(&self.crypto, entropy, context, sealed)
    }

    /// Whether `key` is the recovery key of `group_id`'s device roster, or
    /// may yet be through a branch that branch selection can still pick.
    ///
    /// No branch forks below the oldest selectable epoch: the tip less the
    /// rewind horizon, whose retained anchor this device holds. Only this
    /// device knows the key, so a branch forking at or after that epoch
    /// holds it only if the roster held it where the branch forks, or the
    /// branch carries a commit of this device's that replaces the account
    /// entry, staged there or later. The selected roster held the key
    /// anywhere since that epoch only if it did at that epoch or such a
    /// commit set it. Each such commit keeps its record until the horizon
    /// ([`Self::own_account_entry_change_retained`]). So `false` means the
    /// roster holds the key neither now nor at that epoch's anchor and the
    /// engine keeps no account-entry commit of this device's: no branch that
    /// can still be picked holds the key, and none will, since nothing is
    /// left to re-issue and the records never come back.
    ///
    /// Anything missing counts as `true`: no anchor at the oldest
    /// selectable epoch (pruned, never stored, or a group younger than the
    /// horizon), an anchor older than it, or a roster that does not decode.
    pub fn recovery_key_selectable(
        &self,
        group_id: &GroupId,
        key: &[u8],
    ) -> Result<bool, EngineError> {
        let holds = |group: &MlsGroup| {
            account_entry_of_group(group)
                .is_none_or(|entry| entry.recovery_public_key.as_deref() == Some(key))
        };
        if self.own_account_entry_change_retained(group_id)?
            || holds(&self.load_mls_group(group_id)?)
        {
            return Ok(true);
        }
        let Some(oldest) = self.oldest_selectable_epoch(group_id)? else {
            return Ok(true);
        };
        Ok(with_retained_anchor_group(
            &self.storage,
            &self.crypto,
            group_id,
            oldest,
            RewindSite::AccountEntrySource,
            &format!("{:032x}", rand::random::<u128>()),
            |group, _| Ok(Some(holds(group))),
        )?
        .unwrap_or(true))
    }

    /// Whether this device has a commit that replaces `group_id`'s account
    /// entry queued, or one staged whose record the engine still keeps:
    /// every one staged within the rewind horizon, whatever became of it,
    /// and any whose re-issue is owed. Until none is left, branch selection
    /// may still withdraw or restore this device's change, or the engine
    /// re-issue it. A kept record goes only once its source epoch is past
    /// the horizon, and never comes back.
    pub fn own_account_entry_change_retained(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        self.ensure_group_live(group_id)?;
        let replaces_account_entry =
            |intent: &SendIntent| matches!(intent, SendIntent::ReplaceAccountEntry { .. });
        Ok(self
            .storage
            .list_queued_outbound_intents(group_id)?
            .iter()
            .any(|queued| replaces_account_entry(&queued.intent))
            || self
                .storage
                .list_own_commit_intents(Some(group_id))?
                .iter()
                .any(|record| replaces_account_entry(&record.intent)))
    }

    /// The tip of `group_id` less the rewind horizon, when this device holds
    /// that epoch's retained anchor and none older. Anchors below the
    /// horizon are pruned as the tip advances, so an older one means the tip
    /// moved back, and branches below the horizon may come back with it.
    fn oldest_selectable_epoch(&self, group_id: &GroupId) -> Result<Option<EpochId>, EngineError> {
        let tip = self
            .stored_group_record(group_id)?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?
            .epoch;
        let max_rewind = self
            .convergence_policy_for_group(group_id)
            .map_err(|error| EngineError::Backend(format!("convergence policy: {error:?}")))?
            .convergence
            .max_rewind_commits;
        let oldest = tip.0.saturating_sub(max_rewind);
        let mut held = false;
        for name in self.storage.list_group_snapshots(group_id)? {
            match retained_anchor_epoch_from_snapshot_name(&name) {
                Some(epoch) if epoch < oldest => return Ok(None),
                Some(epoch) => held |= epoch == oldest,
                None => {}
            }
        }
        Ok(held.then_some(EpochId(oldest)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history_key::{generate_history_key_pair, seal_history};
    use openmls_rust_crypto::RustCrypto;

    const CONTEXT: &[u8] = b"backup id and index hash";

    #[test]
    fn the_same_entropy_always_derives_the_same_x25519_key() {
        let crypto = RustCrypto::default();
        let first = derive_recovery_key_pair(&crypto, &[7; RECOVERY_ENTROPY_LEN]).unwrap();
        let again = derive_recovery_key_pair(&crypto, &[7; RECOVERY_ENTROPY_LEN]).unwrap();
        let other = derive_recovery_key_pair(&crypto, &[8; RECOVERY_ENTROPY_LEN]).unwrap();
        assert_eq!(first.public.len(), 32);
        assert_eq!(first.public, again.public);
        assert_eq!(first.private.as_ref(), again.private.as_ref());
        assert_ne!(first.public, other.public);
    }

    /// The derivation's test vectors, shared with the spec: all-zero
    /// entropy, whose words are "abandon" eleven times then "about", and
    /// `0x7f` repeated, whose words are "legal winner thank year wave sausage
    /// worth useful legal winner thank yellow". Checked against an independent
    /// implementation of HKDF and RFC 9180's `DeriveKeyPair`.
    #[test]
    fn the_published_vectors_derive() {
        let crypto = RustCrypto::default();
        for (entropy, private, public) in [
            (
                [0; RECOVERY_ENTROPY_LEN],
                "f99da3bd75751479570bd7d7a807bebb49c8da68aed12e813862cccdff5a577d",
                "aed5608fc1960f7992decafb36786d19508dce48e02288785cf24e557d58a368",
            ),
            (
                [0x7f; RECOVERY_ENTROPY_LEN],
                "8570ead0cc10c1ae63c6357959fdb15996475dabe3b781c4ebecdacb2015ef83",
                "9076c238afd9311184e7dda595f7d42f5c73b48bff561e88482c4435d5cb5f10",
            ),
        ] {
            let pair = derive_recovery_key_pair(&crypto, &entropy).unwrap();
            assert_eq!(hex::encode(pair.private.as_ref()), private);
            assert_eq!(hex::encode(&pair.public), public);
        }
    }

    #[test]
    fn a_sealed_value_opens_only_with_its_words_and_context() {
        let crypto = RustCrypto::default();
        let entropy = [3; RECOVERY_ENTROPY_LEN];
        let public = derive_recovery_key_pair(&crypto, &entropy).unwrap().public;
        let sealed = seal_to_recovery_key(&crypto, &public, CONTEXT, b"archive key").unwrap();

        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &sealed).unwrap(),
            Some(b"archive key".to_vec())
        );
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, b"another", &sealed).unwrap(),
            None
        );
        assert_eq!(
            open_with_recovery_key(&crypto, &[4; RECOVERY_ENTROPY_LEN], CONTEXT, &sealed).unwrap(),
            None
        );
        let mut trailing = sealed.clone();
        trailing.push(0);
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &trailing).unwrap(),
            None
        );
    }

    #[test]
    fn a_key_that_is_no_x25519_public_key_seals_nothing() {
        let crypto = RustCrypto::default();
        for bad in [vec![], vec![7; 31], vec![7; 33]] {
            assert_eq!(
                seal_to_recovery_key(&crypto, &bad, CONTEXT, b"archive key"),
                None
            );
        }
    }

    /// A value sealed to the same key and context as history never opens as
    /// a backup value, nor the other way round.
    #[test]
    fn the_label_separates_backups_from_history() {
        let crypto = RustCrypto::default();
        let entropy = [5; RECOVERY_ENTROPY_LEN];
        let public = derive_recovery_key_pair(&crypto, &entropy).unwrap().public;
        let as_history = seal_history(
            &crypto,
            RECOVERY_CIPHERSUITE,
            &public,
            CONTEXT,
            b"archive key",
        )
        .unwrap();
        assert_eq!(
            open_with_recovery_key(&crypto, &entropy, CONTEXT, &as_history).unwrap(),
            None
        );

        let history = generate_history_key_pair(&crypto, RECOVERY_CIPHERSUITE).unwrap();
        let as_backup =
            seal_to_recovery_key(&crypto, &history.public, CONTEXT, b"bundle key").unwrap();
        assert_eq!(
            crate::history_key::open_history(
                &crypto,
                RECOVERY_CIPHERSUITE,
                &history.private,
                CONTEXT,
                &as_backup
            ),
            None
        );
    }
}
