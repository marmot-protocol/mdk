//! The SAS construction, transcribed from Matrix's `m.sas.v1`.
//!
//! Matrix's reviewed design, with its `curve25519-hkdf-sha256` key agreement,
//! `hkdf-hmac-sha256.v2` MACs and SHA-256 commitment: X25519 ephemeral keys,
//! a commitment the committing side sends before it sees the other key, the
//! code from HKDF-SHA256 over the shared secret, and one HMAC-SHA256 per
//! confirmed item under a key HKDF derives from the same secret. Only the
//! byte encodings are Marmot's: each input below is a Marmot binary profile
//! structure, with fixed-size fields bare and variable-length fields behind a
//! QUIC variable-length prefix, where Matrix joins strings. Nothing here adds
//! to Matrix's cryptography.
//!
//! The new device plays the role of Matrix's accepting device: it commits to
//! its key in the request and reveals it last.

use cgka_traits::app_components::encode_quic_varint;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::code::SasCode;
use crate::types::{AccountKey, ExchangeKey, KeyPackageEventId, KeyPackageRef, SessionId, SlotId};

pub(crate) const COMMITMENT_LABEL: &[u8] = b"marmot-pairing-v1-commitment";
pub(crate) const SAS_LABEL: &[u8] = b"marmot-pairing-v1-sas";
pub(crate) const MAC_LABEL: &[u8] = b"marmot-pairing-v1-mac";

/// HKDF output the code uses: Matrix's six bytes for the emoji method.
pub(crate) const SAS_BYTES_LEN: usize = 6;

/// Length of each confirmation's HMAC-SHA256 key.
const MAC_KEY_LEN: usize = 32;

/// Which side sends a confirmation: the `sender_role` byte of its MAC info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MacSender {
    NewDevice = 1,
    ExistingDevice = 2,
}

/// What a confirmation covers: the `item` byte of its MAC info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MacItem {
    /// The new device's exact `KeyPackageRef`.
    KeyPackageRef = 1,
    /// The device-group id the existing device adds the new device to.
    DeviceGroupId = 2,
}

/// What the new device's request names, which its commitment covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBinding {
    pub session_id: SessionId,
    pub account: AccountKey,
    pub key_package_event_id: KeyPackageEventId,
    pub key_package_ref: KeyPackageRef,
}

/// Everything the code and confirmations bind besides the two keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionBinding {
    pub(crate) session_id: SessionId,
    pub(crate) account: AccountKey,
    pub(crate) key_package_ref: KeyPackageRef,
    pub(crate) existing_device_slot: SlotId,
}

impl SessionBinding {
    pub(crate) fn new(request: &RequestBinding, existing_device_slot: SlotId) -> Self {
        Self {
            session_id: request.session_id,
            account: request.account,
            key_package_ref: request.key_package_ref.clone(),
            existing_device_slot,
        }
    }
}

/// One side's ephemeral X25519 key pair. [`EphemeralKey::agree`] consumes
/// it, so a key is used for exactly one agreement.
pub(crate) struct EphemeralKey {
    secret: StaticSecret,
    public: ExchangeKey,
}

impl EphemeralKey {
    pub(crate) fn generate() -> Self {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self::from_secret_bytes(*bytes)
    }

    pub(crate) fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = ExchangeKey::new(PublicKey::from(&secret).to_bytes());
        Self { secret, public }
    }

    pub(crate) fn public(&self) -> ExchangeKey {
        self.public
    }

    /// X25519 with `peer`. `None` when the result is all zeros: `peer` is a
    /// low-order point, which no honest device sends.
    pub(crate) fn agree(self, peer: &ExchangeKey) -> Option<SharedSecret> {
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(*peer.as_bytes()));
        shared
            .was_contributory()
            .then(|| SharedSecret(Zeroizing::new(shared.to_bytes())))
    }
}

/// The X25519 shared secret, the input keying material of every derivation.
pub(crate) struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    /// The six code bytes: HKDF-SHA256 with no salt over the shared secret,
    /// with [`sas_info`] as info.
    pub(crate) fn code(
        &self,
        binding: &SessionBinding,
        new_device_key: &ExchangeKey,
        existing_device_key: &ExchangeKey,
    ) -> SasCode {
        let info = sas_info(binding, new_device_key, existing_device_key);
        let mut bytes = [0_u8; SAS_BYTES_LEN];
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(&info, &mut bytes)
            .expect("six bytes is a valid HKDF-SHA256 length");
        SasCode::from_bytes(bytes)
    }

    /// HMAC-SHA256 of `item_value` under the key [`mac_info`] names.
    pub(crate) fn mac(
        &self,
        binding: &SessionBinding,
        sender: MacSender,
        item: MacItem,
        item_value: &[u8],
    ) -> [u8; 32] {
        self.mac_instance(binding, sender, item, item_value)
            .finalize()
            .into_bytes()
            .into()
    }

    /// Constant-time check of `mac` against [`SharedSecret::mac`].
    pub(crate) fn verify_mac(
        &self,
        binding: &SessionBinding,
        sender: MacSender,
        item: MacItem,
        item_value: &[u8],
        mac: &[u8; 32],
    ) -> bool {
        self.mac_instance(binding, sender, item, item_value)
            .verify_slice(mac)
            .is_ok()
    }

    fn mac_instance(
        &self,
        binding: &SessionBinding,
        sender: MacSender,
        item: MacItem,
        item_value: &[u8],
    ) -> Hmac<Sha256> {
        let info = mac_info(binding, sender, item);
        let mut key = Zeroizing::new([0_u8; MAC_KEY_LEN]);
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(&info, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref())
            .expect("HMAC-SHA256 takes any key length");
        let mut message = Vec::with_capacity(item_value.len() + 2);
        put_var_bytes(item_value, &mut message);
        mac.update(&message);
        mac
    }
}

/// The request commitment: SHA-256 of
///
/// ```text
/// struct {
///     opaque label<V> = "marmot-pairing-v1-commitment";
///     opaque new_device_key[32];
///     opaque session_id[32];
///     opaque account[32];
///     opaque key_package_event_id[32];
///     opaque key_package_ref<V>;
/// } PairingCommitmentInput;
/// ```
///
/// Matrix's accepting device hashes its key and the start message the same
/// way.
pub fn commitment(new_device_key: &ExchangeKey, request: &RequestBinding) -> [u8; 32] {
    let mut input = Vec::with_capacity(200);
    put_var_bytes(COMMITMENT_LABEL, &mut input);
    input.extend_from_slice(new_device_key.as_bytes());
    input.extend_from_slice(request.session_id.as_bytes());
    input.extend_from_slice(request.account.as_bytes());
    input.extend_from_slice(request.key_package_event_id.as_bytes());
    put_var_bytes(request.key_package_ref.as_slice(), &mut input);
    Sha256::digest(&input).into()
}

/// The code's HKDF info:
///
/// ```text
/// struct {
///     opaque label<V> = "marmot-pairing-v1-sas";
///     opaque session_id[32];
///     opaque account[32];
///     opaque key_package_ref<V>;
///     opaque new_device_key[32];
///     opaque existing_device_slot[32];
///     opaque existing_device_key[32];
/// } PairingSasInfo;
/// ```
///
/// Matrix's info names each side's identity and key, then the transaction.
pub(crate) fn sas_info(
    binding: &SessionBinding,
    new_device_key: &ExchangeKey,
    existing_device_key: &ExchangeKey,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(256);
    put_var_bytes(SAS_LABEL, &mut info);
    info.extend_from_slice(binding.session_id.as_bytes());
    info.extend_from_slice(binding.account.as_bytes());
    put_var_bytes(binding.key_package_ref.as_slice(), &mut info);
    info.extend_from_slice(new_device_key.as_bytes());
    info.extend_from_slice(binding.existing_device_slot.as_bytes());
    info.extend_from_slice(existing_device_key.as_bytes());
    info
}

/// A confirmation key's HKDF info:
///
/// ```text
/// struct {
///     opaque label<V> = "marmot-pairing-v1-mac";
///     uint8 sender_role;            // 1 new device, 2 existing device
///     opaque session_id[32];
///     opaque account[32];
///     opaque key_package_ref<V>;
///     opaque existing_device_slot[32];
///     uint8 item;                   // 1 KeyPackageRef, 2 device-group id
/// } PairingMacInfo;
/// ```
///
/// Matrix's MAC info names the sender, the receiver, the transaction and the
/// item; the MAC itself covers the item's value as `opaque value<V>`.
pub(crate) fn mac_info(binding: &SessionBinding, sender: MacSender, item: MacItem) -> Vec<u8> {
    let mut info = Vec::with_capacity(200);
    put_var_bytes(MAC_LABEL, &mut info);
    info.push(sender as u8);
    info.extend_from_slice(binding.session_id.as_bytes());
    info.extend_from_slice(binding.account.as_bytes());
    put_var_bytes(binding.key_package_ref.as_slice(), &mut info);
    info.extend_from_slice(binding.existing_device_slot.as_bytes());
    info.push(item as u8);
    info
}

fn put_var_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_quic_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}
