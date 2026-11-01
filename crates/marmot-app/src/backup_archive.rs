//! Backup archives (mdk#2628 4.4b, D71): an account's chat history and small
//! state, written as Blossom blobs that only its recovery words open.
//!
//! A backup is blobs and one head, each one Blossom blob at the SHA-256 of
//! its bytes:
//!
//! - one blob per history bundle (`history_bundle.rs`), encrypted as a
//!   bundle is, but under a key the backup's archive key derives;
//! - at most one blob of small-state items, `{"v":1,"items":[...]}` as an
//!   update writes them, without the update's size limit, encrypted the same
//!   way under its own derived key and [`SMALL_STATE_AAD`];
//! - the head, which holds the archive key sealed to the account's recovery
//!   key and the index of the blobs, encrypted under a key the recovery
//!   key's public half derives.
//!
//! The head and the index are UTF-8 JSON objects written without
//! whitespace, members in this order, base64 standard with padding:
//!
//! ```text
//! head  = {"v":1,"id":"<32 hex>","key":"<base64>","index":"<base64>"}
//! index = {"v":1,"written_at":t,"writer":"<slot hex>","small_state":L?,"chats":[C,...]}
//! C     = {"chat":"<MLS group id hex>","blobs":[B,...]}
//! B     = {"from":P,"to":P,"expires":t?,"sha256":"<64 hex>","size":n,"server":"<url>"}
//! L     = {"sha256":"<64 hex>","size":n,"server":"<url>"}
//! ```
//!
//! `P` is a chat position as bundles write it. Each `B` is one bundle blob:
//! the stretch its bundle vouches for, when every event in it has expired
//! (absent when one never does), and where it is. Blobs are numbered from 0
//! in index order, each chat's in turn. Every key comes from HKDF-SHA256:
//!
//! ```text
//! archive prk = HKDF-Extract(salt = "marmot backup v1", IKM = archive key)
//! blob n      = HKDF-Expand(archive prk, "marmot backup blob" || uint32(n), 32)
//! small state = HKDF-Expand(archive prk, "marmot backup small state", 32)
//! index       = HKDF-Expand(HKDF-Extract(salt = "marmot backup index v1",
//!                                        IKM = recovery public key), id, 32)
//! ```
//!
//! A fresh random archive key and backup id make every key one-use, so each
//! blob and the index use ChaCha20-Poly1305 with an all-zero nonce. `key` is
//! the archive key sealed to the recovery key ([`marmot_session::seal_to_recovery_key`])
//! with [`seal_context`], which binds the id and the index ciphertext's
//! SHA-256, so an index that is altered or taken from another head leaves the
//! archive key sealed. Anyone holding the public half reads the index: the
//! account's devices, current and former, see which chats and stretches a
//! backup holds and where its blobs are. Only the words open a blob.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cgka_traits::app_components::{DeviceSlotId, encode_component_vectors};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_sqlite::SmallStateItem;
use zeroize::Zeroizing;

use crate::AppError;
use crate::history_bundle::{
    ChatPosition, HISTORY_BUNDLE_MAX_PLAINTEXT, HistoryBundle, MAX_INTEGER, is_chat_hex,
    is_hash_hex, is_lower_hex, open_history_bundle, present, seal_history_bundle_with_key,
};
use crate::history_delivery::blossom_server_is_valid;
use crate::small_state::{decode_small_state_items, encode_small_state_items};

/// The length of a backup id.
pub(crate) const BACKUP_ID_LEN: usize = 16;
/// The longest blob a backup holds: a bundle's most plaintext and the AEAD
/// tag. The small-state blob holds no more plaintext than a bundle.
pub(crate) const MAX_BACKUP_BLOB_BYTES: u64 = HISTORY_BUNDLE_MAX_PLAINTEXT as u64 + TAG_LEN as u64;
/// The longest head.
pub(crate) const MAX_BACKUP_HEAD_BYTES: usize = HISTORY_BUNDLE_MAX_PLAINTEXT;
const BACKUP_VERSION: u64 = 1;
const TAG_LEN: usize = 16;
const ARCHIVE_SALT: &[u8] = b"marmot backup v1";
const BLOB_INFO: &[u8] = b"marmot backup blob";
const SMALL_STATE_INFO: &[u8] = b"marmot backup small state";
/// The small-state blob's associated data.
const SMALL_STATE_AAD: &[u8] = b"marmot backup small state v1";
const INDEX_SALT: &[u8] = b"marmot backup index v1";
/// The index's associated data.
const INDEX_AAD: &[u8] = b"marmot backup index v1";
/// The sealed archive key's context starts with what it is for.
const SEAL_PURPOSE: &[u8] = b"marmot backup v1";

/// A backup's archive key: fresh for each backup and the source of every
/// blob's key. Only its head holds it, sealed; it is never stored.
pub(crate) struct ArchiveKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for ArchiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveKey(redacted)")
    }
}

impl ArchiveKey {
    pub(crate) fn generate() -> Self {
        let mut key = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
        Self(key)
    }

    /// The archive key a head's sealed key opened to, or none unless it is
    /// exactly 32 bytes.
    pub(crate) fn from_opened(opened: &[u8]) -> Option<Self> {
        let mut key = Zeroizing::new([0_u8; 32]);
        (opened.len() == 32).then(|| {
            key.copy_from_slice(opened);
            Self(key)
        })
    }

    fn expand(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(Some(ARCHIVE_SALT), self.0.as_slice())
            .expand(info, key.as_mut_slice())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }

    fn blob_key(&self, number: u32) -> Zeroizing<[u8; 32]> {
        let mut info = BLOB_INFO.to_vec();
        info.extend_from_slice(&number.to_be_bytes());
        self.expand(&info)
    }

    fn small_state_key(&self) -> Zeroizing<[u8; 32]> {
        self.expand(SMALL_STATE_INFO)
    }
}

/// A fresh backup id.
pub(crate) fn new_backup_id() -> [u8; BACKUP_ID_LEN] {
    let mut id = [0_u8; BACKUP_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// One encrypted blob, and the SHA-256 Blossom names it by.
pub(crate) struct SealedBlob {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) sha256: [u8; 32],
}

/// Where a blob is: its SHA-256, its size and the Blossom server that holds
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlobLocator {
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) server: String,
}

impl BlobLocator {
    pub(crate) fn new(sealed: &SealedBlob, server: String) -> Self {
        Self {
            sha256: hex::encode(sealed.sha256),
            size: sealed.ciphertext.len() as u64,
            server,
        }
    }

    fn is_well_formed(&self) -> bool {
        is_hash_hex(&self.sha256)
            && (1..=MAX_BACKUP_BLOB_BYTES).contains(&self.size)
            && blossom_server_is_valid(&self.server)
    }

    /// Whether `ciphertext` is the blob this names, by size and hash.
    fn names(&self, ciphertext: &[u8]) -> bool {
        ciphertext.len() as u64 == self.size
            && hex::encode(Sha256::digest(ciphertext)) == self.sha256
    }

    fn sha256_bytes(&self) -> Result<[u8; 32], AppError> {
        let mut hash = [0_u8; 32];
        hex::decode_to_slice(&self.sha256, &mut hash).map_err(|_| backup_error("backup_format"))?;
        Ok(hash)
    }
}

/// What a backup holds and where: readable with the recovery key's public
/// half.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupIndex {
    pub(crate) v: u64,
    pub(crate) written_at: u64,
    pub(crate) writer: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub(crate) small_state: Option<BlobLocator>,
    pub(crate) chats: Vec<IndexChat>,
}

/// One chat's bundle blobs, in chat order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexChat {
    pub(crate) chat: String,
    pub(crate) blobs: Vec<IndexBlob>,
}

/// One bundle blob: the stretch its bundle vouches for, when everything in
/// it has expired, and where it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexBlob {
    pub(crate) from: ChatPosition,
    pub(crate) to: ChatPosition,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub(crate) expires: Option<u64>,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) server: String,
}

impl IndexBlob {
    /// The blob `sealed` of `bundle`, held by `server`.
    pub(crate) fn new(bundle: &HistoryBundle, sealed: &SealedBlob, server: String) -> Self {
        let BlobLocator {
            sha256,
            size,
            server,
        } = BlobLocator::new(sealed, server);
        Self {
            from: bundle.from.clone(),
            to: bundle.to.clone(),
            expires: bundle_expires(bundle),
            sha256,
            size,
            server,
        }
    }

    pub(crate) fn locator(&self) -> BlobLocator {
        BlobLocator {
            sha256: self.sha256.clone(),
            size: self.size,
            server: self.server.clone(),
        }
    }

    fn is_well_formed(&self) -> bool {
        self.from.is_well_formed()
            && self.to.is_well_formed()
            && self.from <= self.to
            && self.expires.is_none_or(|at| at <= MAX_INTEGER)
            && self.locator().is_well_formed()
    }
}

/// When every event in `bundle` has expired, or none when one never does: its
/// retention is `0`, disappearing messages off, or it has none.
fn bundle_expires(bundle: &HistoryBundle) -> Option<u64> {
    bundle
        .events
        .iter()
        .try_fold(0, |latest: u64, event| match event.retention {
            Some(seconds) if seconds > 0 => Some(
                latest.max(
                    event
                        .event
                        .created_at
                        .saturating_add(seconds)
                        .min(MAX_INTEGER),
                ),
            ),
            _ => None,
        })
}

impl BackupIndex {
    /// An index of no blobs yet, written at `written_at` by the device at
    /// `writer`.
    pub(crate) fn new(written_at: u64, writer: &DeviceSlotId) -> Self {
        Self {
            v: BACKUP_VERSION,
            written_at,
            writer: hex::encode(writer),
            small_state: None,
            chats: Vec::new(),
        }
    }

    /// The number the next bundle blob takes.
    pub(crate) fn next_blob_number(&self) -> Result<u32, AppError> {
        let count = self
            .chats
            .iter()
            .map(|chat| chat.blobs.len())
            .sum::<usize>();
        u32::try_from(count).map_err(|_| backup_error("backup_too_large"))
    }

    /// Adds `blob`, of the chat `chat`, after every blob added so far. A
    /// chat's blobs are added together, in chat order.
    pub(crate) fn push_blob(&mut self, chat: &[u8], blob: IndexBlob) -> Result<(), AppError> {
        let chat = hex::encode(chat);
        match self.chats.iter().position(|held| held.chat == chat) {
            Some(at) if at + 1 == self.chats.len() => self.chats[at].blobs.push(blob),
            Some(_) => return Err(backup_error("backup_chat_order")),
            None => self.chats.push(IndexChat {
                chat,
                blobs: vec![blob],
            }),
        }
        Ok(())
    }

    /// Every bundle blob with its number and its chat, in index order.
    pub(crate) fn blobs(&self) -> impl Iterator<Item = (u32, &IndexChat, &IndexBlob)> {
        self.chats
            .iter()
            .flat_map(|chat| chat.blobs.iter().map(move |blob| (chat, blob)))
            .zip(0_u32..)
            .map(|((chat, blob), number)| (number, chat, blob))
    }

    fn encode(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self).map_err(|_| backup_error("backup_format"))
    }

    /// Decode an index, refusing it whole when anything in it breaks the
    /// format: a missing, extra or repeated member, a value out of range, a
    /// chat named twice or with no blobs, or a stretch whose `from` is after
    /// its `to`. Whitespace and member order are not checked, which only the
    /// writer's rule fixes.
    fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        let index: Self =
            serde_json::from_slice(bytes).map_err(|_| backup_error("backup_format"))?;
        let mut chats = std::collections::BTreeSet::new();
        let well_formed = index.v == BACKUP_VERSION
            && index.written_at <= MAX_INTEGER
            && is_hash_hex(&index.writer)
            && index
                .small_state
                .as_ref()
                .is_none_or(BlobLocator::is_well_formed)
            && index.chats.iter().all(|chat| {
                is_chat_hex(&chat.chat)
                    && chats.insert(chat.chat.as_str())
                    && !chat.blobs.is_empty()
                    && chat.blobs.iter().all(IndexBlob::is_well_formed)
            })
            && index.next_blob_number().is_ok();
        if !well_formed {
            return Err(backup_error("backup_format"));
        }
        Ok(index)
    }
}

/// Bundle blob `number` of a backup: `bundle`, encrypted as bundles are,
/// under the key `archive_key` derives for that number.
pub(crate) fn seal_backup_bundle(
    archive_key: &ArchiveKey,
    number: u32,
    bundle: &HistoryBundle,
) -> Result<SealedBlob, AppError> {
    let sealed = seal_history_bundle_with_key(bundle, archive_key.blob_key(number))?;
    Ok(SealedBlob {
        ciphertext: sealed.ciphertext,
        sha256: sealed.ciphertext_sha256,
    })
}

/// Open bundle blob `number`, which the index lists as `blob` of `chat`.
/// Refused unless it is the blob the index names, it decrypts under that
/// number's key, and its bundle names that chat and that stretch.
pub(crate) fn open_backup_bundle(
    archive_key: &ArchiveKey,
    number: u32,
    chat: &IndexChat,
    blob: &IndexBlob,
    ciphertext: &[u8],
) -> Result<HistoryBundle, AppError> {
    if !blob.locator().names(ciphertext) {
        return Err(backup_error("backup_blob_hash"));
    }
    let bundle = open_history_bundle(
        &archive_key.blob_key(number),
        &blob.locator().sha256_bytes()?,
        ciphertext,
    )?;
    if bundle.chat != chat.chat || bundle.from != blob.from || bundle.to != blob.to {
        return Err(backup_error("backup_blob_mismatch"));
    }
    Ok(bundle)
}

/// A backup's small-state blob: every valid item of `items`, encrypted under
/// the key `archive_key` derives for it. Refused when it would hold more
/// plaintext than a bundle.
pub(crate) fn seal_backup_small_state(
    archive_key: &ArchiveKey,
    items: &[SmallStateItem],
) -> Result<SealedBlob, AppError> {
    let plaintext = Zeroizing::new(encode_small_state_items(items).into_bytes());
    if plaintext.len() > HISTORY_BUNDLE_MAX_PLAINTEXT {
        return Err(backup_error("backup_too_large"));
    }
    let ciphertext = cipher(&archive_key.small_state_key())
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: &plaintext,
                aad: SMALL_STATE_AAD,
            },
        )
        .map_err(|_| backup_error("backup_seal"))?;
    let sha256 = Sha256::digest(&ciphertext).into();
    Ok(SealedBlob { ciphertext, sha256 })
}

/// Open the small-state blob `locator` names. Refused unless it is that
/// blob, it decrypts, and it is an items object; an item that breaks the
/// item rules is skipped, as in an update.
pub(crate) fn open_backup_small_state(
    archive_key: &ArchiveKey,
    locator: &BlobLocator,
    ciphertext: &[u8],
) -> Result<Vec<SmallStateItem>, AppError> {
    if !locator.names(ciphertext) {
        return Err(backup_error("backup_blob_hash"));
    }
    let plaintext = Zeroizing::new(
        cipher(&archive_key.small_state_key())
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad: SMALL_STATE_AAD,
                },
            )
            .map_err(|_| backup_error("backup_decrypt"))?,
    );
    let content = std::str::from_utf8(&plaintext).map_err(|_| backup_error("backup_format"))?;
    decode_small_state_items(content, HISTORY_BUNDLE_MAX_PLAINTEXT)
}

/// A backup's head: its id, its archive key sealed to the recovery key, and
/// its index's ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BackupHead {
    pub(crate) id: [u8; BACKUP_ID_LEN],
    sealed_key: Vec<u8>,
    index: Vec<u8>,
}

impl BackupHead {
    /// The head of backup `id`: `archive_key` sealed to `recovery_public_key`
    /// and `index` encrypted under the key that public half derives. Refused
    /// with `backup_recovery_key` when it is no key a value can be sealed
    /// to, and with `backup_too_large` when the head would be longer than
    /// [`MAX_BACKUP_HEAD_BYTES`].
    pub(crate) fn seal(
        id: [u8; BACKUP_ID_LEN],
        archive_key: &ArchiveKey,
        recovery_public_key: &[u8],
        index: &BackupIndex,
    ) -> Result<Self, AppError> {
        let index = cipher(&index_key(recovery_public_key, &id))
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: &index.encode()?,
                    aad: INDEX_AAD,
                },
            )
            .map_err(|_| backup_error("backup_seal"))?;
        let sealed_key = marmot_session::seal_to_recovery_key(
            recovery_public_key,
            &seal_context(&id, &index),
            archive_key.0.as_slice(),
        )
        .ok_or(backup_error("backup_recovery_key"))?;
        let head = Self {
            id,
            sealed_key,
            index,
        };
        if head.encode().len() > MAX_BACKUP_HEAD_BYTES {
            return Err(backup_error("backup_too_large"));
        }
        Ok(head)
    }

    /// The head's bytes, in the canonical form.
    pub(crate) fn encode(&self) -> Vec<u8> {
        format!(
            r#"{{"v":{BACKUP_VERSION},"id":"{}","key":"{}","index":"{}"}}"#,
            hex::encode(self.id),
            BASE64_STANDARD.encode(&self.sealed_key),
            BASE64_STANDARD.encode(&self.index),
        )
        .into_bytes()
    }

    /// Decode a head, refusing it when it is longer than
    /// [`MAX_BACKUP_HEAD_BYTES`] or breaks the format: a missing, extra or
    /// repeated member, another version, an id that is not 32 lowercase
    /// hexadecimal characters, or a `key` or `index` that is not non-empty
    /// base64.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        let invalid = || backup_error("backup_format");
        if bytes.len() > MAX_BACKUP_HEAD_BYTES {
            return Err(backup_error("backup_too_large"));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            v: u64,
            id: String,
            key: String,
            index: String,
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let mut id = [0_u8; BACKUP_ID_LEN];
        if wire.v != BACKUP_VERSION
            || !is_lower_hex(&wire.id)
            || hex::decode_to_slice(&wire.id, &mut id).is_err()
        {
            return Err(invalid());
        }
        let base64 = |value: &str| {
            BASE64_STANDARD
                .decode(value)
                .ok()
                .filter(|bytes| !bytes.is_empty())
                .ok_or_else(invalid)
        };
        Ok(Self {
            id,
            sealed_key: base64(&wire.key)?,
            index: base64(&wire.index)?,
        })
    }

    /// The index, opened with the recovery key's public half. Refused when
    /// it does not open with that key or breaks the format.
    pub(crate) fn open_index(&self, recovery_public_key: &[u8]) -> Result<BackupIndex, AppError> {
        let plaintext = cipher(&index_key(recovery_public_key, &self.id))
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: &self.index,
                    aad: INDEX_AAD,
                },
            )
            .map_err(|_| backup_error("backup_decrypt"))?;
        BackupIndex::decode(&plaintext)
    }

    /// The context and the sealed value the archive key opens from, with
    /// the private half the recovery words derive.
    pub(crate) fn sealed_archive_key(&self) -> (Vec<u8>, &[u8]) {
        (seal_context(&self.id, &self.index), &self.sealed_key)
    }
}

/// The context the archive key is sealed with: the purpose, the backup id
/// and the index ciphertext's SHA-256, each a length-prefixed vector.
fn seal_context(id: &[u8; BACKUP_ID_LEN], index_ciphertext: &[u8]) -> Vec<u8> {
    encode_component_vectors(&[SEAL_PURPOSE, id, &Sha256::digest(index_ciphertext)])
}

/// The key a backup's index is encrypted under: anyone with the recovery
/// key's public half derives it.
fn index_key(recovery_public_key: &[u8], id: &[u8; BACKUP_ID_LEN]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(INDEX_SALT), recovery_public_key)
        .expand(id, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

fn backup_error(reason: &'static str) -> AppError {
    AppError::DeviceGroupRefused(reason)
}

#[cfg(test)]
mod tests;
