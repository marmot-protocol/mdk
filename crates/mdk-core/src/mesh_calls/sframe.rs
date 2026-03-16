//! SFrame encryption/decryption implementation (RFC 9605)
//!
//! SFrame provides end-to-end encryption of media frames above the transport layer.
//! This allows SFUs to route media without accessing the plaintext content.
//!
//! ## Wire Format (RFC 9605 §4.3)
//!
//! ```text
//! Config byte: |X|  K  |Y|  C  |  (8 bits total)
//!   X=0: K is the Key ID (0-7), inline
//!   X=1: K is the byte-length of extended Key ID, minus 1
//!   Y=0: C is the Counter (0-7), inline
//!   Y=1: C is the byte-length of extended Counter, minus 1
//!
//! After config byte: extended CTR bytes (if Y=1), then extended KID bytes (if X=1)
//! Then: ciphertext + GCM tag
//! ```

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::types::{MediaType, MeshCallError, SFrameBits};

/// SFrame cipher suite identifier
const CIPHER_SUITE_AES_128_GCM_SHA256_128: u16 = 0x0001;

/// AES-128 key size in bytes
const NK: usize = 16;
/// Nonce size in bytes
const NN: usize = 12;
/// Authentication tag size in bytes
const NT: usize = 16;

/// Default CTR budget: 2^32 frames per epoch (~37 hours at 30fps).
const DEFAULT_CTR_BUDGET: u64 = 1u64 << 32;

/// SFrame key derived from MLS
#[derive(Debug, Clone)]
pub struct SFrameKey {
    /// The encryption key (16 bytes)
    pub key: [u8; NK],
    /// The salt for nonce derivation (12 bytes)
    pub salt: [u8; NN],
}

/// SFrame counter for a sender
#[derive(Debug, Clone, Copy)]
pub struct SFrameCounter {
    /// Current counter value
    value: u64,
    /// Maximum counter value (budget)
    budget: u64,
}

impl Default for SFrameCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SFrameCounter {
    /// Create a new counter starting at 0 with default budget
    pub fn new() -> Self {
        Self {
            value: 0,
            budget: DEFAULT_CTR_BUDGET,
        }
    }

    /// Get the next counter value and increment
    pub fn next(&mut self) -> Result<u64, MeshCallError> {
        if self.value >= self.budget {
            return Err(MeshCallError::SFrameEncryption(
                "CTR budget exhausted: epoch rotation required".into(),
            ));
        }
        let current = self.value;
        self.value = self.value.checked_add(1).ok_or_else(|| {
            MeshCallError::SFrameEncryption("CTR overflow".into())
        })?;
        Ok(current)
    }

    /// Get current value without incrementing
    pub fn current(&self) -> u64 {
        self.value
    }

    /// Reset counter to 0 (called on epoch transition)
    pub fn reset(&mut self) {
        self.value = 0;
    }
}

/// SFrame context for a call participant
#[derive(Debug, Clone)]
pub struct SFrameContext {
    /// SFrame bits configuration
    pub sframe_bits: SFrameBits,
    /// Current epoch counter
    pub epoch: u8,
    /// Sender's leaf index
    pub sender_leaf: u32,
    /// Encryption keys by (media_type, epoch, sender)
    keys: std::collections::HashMap<(MediaType, u8, u32), SFrameKey>,
    /// Counters by media type (sender-side only)
    counters: std::collections::HashMap<MediaType, SFrameCounter>,
    /// Highest CTR seen per (media_type, sender, epoch) for replay protection
    max_ctr_seen: std::collections::HashMap<(MediaType, u32, u8), u64>,
    /// Whether we have received a frame from each (media_type, sender, epoch)
    has_received: std::collections::HashMap<(MediaType, u32, u8), bool>,
    /// Previous epoch keys (for 2-second grace period)
    previous_keys: std::collections::HashMap<(MediaType, u8, u32), SFrameKey>,
    /// Time when previous keys were stored
    previous_keys_timestamp: Option<std::time::Instant>,
}

impl SFrameContext {
    /// Create a new SFrame context
    pub fn new(sframe_bits: SFrameBits, sender_leaf: u32) -> Self {
        Self {
            sframe_bits,
            epoch: 0,
            sender_leaf,
            keys: std::collections::HashMap::new(),
            counters: std::collections::HashMap::new(),
            max_ctr_seen: std::collections::HashMap::new(),
            has_received: std::collections::HashMap::new(),
            previous_keys: std::collections::HashMap::new(),
            previous_keys_timestamp: None,
        }
    }

    /// Set the encryption key for a specific media type, epoch, and sender
    pub fn set_key(&mut self, media_type: MediaType, key: SFrameKey) {
        let key_tuple = (media_type, self.epoch, self.sender_leaf);
        self.keys.insert(key_tuple, key);
    }

    /// Set the encryption key for a remote sender
    pub fn set_remote_key(
        &mut self,
        media_type: MediaType,
        epoch: u8,
        sender_leaf: u32,
        key: SFrameKey,
    ) {
        self.keys.insert((media_type, epoch, sender_leaf), key);
    }

    /// Get or create counter for a media type
    fn get_counter(&mut self, media_type: MediaType) -> &mut SFrameCounter {
        self.counters.entry(media_type).or_default()
    }

    /// Encrypt a frame
    pub fn encrypt(
        &mut self,
        media_type: MediaType,
        plaintext: &[u8],
        metadata: &[u8],
    ) -> Result<Vec<u8>, MeshCallError> {
        let ctr = self.get_counter(media_type).next()?;

        let key_tuple = (media_type, self.epoch, self.sender_leaf);
        let sframe_key = self.keys
            .get(&key_tuple)
            .ok_or_else(|| MeshCallError::SFrameEncryption("Key not found".into()))?;

        let kid = self.sframe_bits.make_kid(media_type, self.sender_leaf, self.epoch);

        // Encode header per RFC 9605 §4.3
        let header = encode_header(ctr, kid);

        // Derive nonce: salt XOR pad(CTR, Nn)
        let nonce_bytes = compute_nonce(&sframe_key.salt, ctr);

        // AAD = header || metadata
        let mut aad = header.clone();
        aad.extend_from_slice(metadata);

        let cipher = Aes128Gcm::new_from_slice(&sframe_key.key)
            .map_err(|e| MeshCallError::SFrameEncryption(format!("Key init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|e| MeshCallError::SFrameEncryption(format!("Encryption failed: {}", e)))?;

        // Output = header || ciphertext (includes GCM tag)
        let mut frame = header;
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }

    /// Decrypt a frame
    pub fn decrypt(
        &mut self,
        frame: &[u8],
        metadata: &[u8],
    ) -> Result<(MediaType, Vec<u8>), MeshCallError> {
        // Parse header per RFC 9605 §4.3
        let (header_len, ctr, kid) = parse_header(frame)?;

        // Parse KID into components
        let (media_type, sender_leaf, epoch) = self.sframe_bits.parse_kid(kid);

        // Replay protection: CTR must be strictly monotonically increasing per sender per epoch
        let recv_key = (media_type, sender_leaf, epoch);
        let has_received = self.has_received.get(&recv_key).copied().unwrap_or(false);
        if has_received {
            let max_ctr = self.max_ctr_seen.get(&recv_key).copied().unwrap_or(0);
            if ctr <= max_ctr {
                return Err(MeshCallError::SFrameDecryption(
                    "Replay detected: CTR not monotonically increasing".into(),
                ));
            }
        }

        // Find the right key - clone to avoid borrow conflict with &mut self
        let sframe_key = if epoch == self.epoch {
            self.keys
                .get(&(media_type, epoch, sender_leaf))
                .or_else(|| self.previous_keys.get(&(media_type, epoch, sender_leaf)))
                .ok_or_else(|| MeshCallError::SFrameDecryption("Key not found".into()))?
                .clone()
        } else {
            // Check if within grace period for previous epoch
            let use_previous = self.previous_keys_timestamp
                .map(|ts| ts.elapsed().as_secs() < 2)
                .unwrap_or(false);

            if use_previous {
                self.previous_keys
                    .get(&(media_type, epoch, sender_leaf))
                    .ok_or(MeshCallError::EpochMismatch {
                        expected: self.epoch,
                        received: epoch,
                    })?
                    .clone()
            } else {
                return Err(MeshCallError::EpochMismatch {
                    expected: self.epoch,
                    received: epoch,
                });
            }
        };

        // Decrypt
        if frame.len() < header_len + NT {
            return Err(MeshCallError::SFrameDecryption("Frame too short".into()));
        }

        let nonce_bytes = compute_nonce(&sframe_key.salt, ctr);

        let mut aad = frame[..header_len].to_vec();
        aad.extend_from_slice(metadata);

        let cipher = Aes128Gcm::new_from_slice(&sframe_key.key)
            .map_err(|e| MeshCallError::SFrameDecryption(format!("Key init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = &frame[header_len..];

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|e| MeshCallError::SFrameDecryption(format!("Decryption failed: {}", e)))?;

        // Update replay protection state after successful decryption
        self.has_received.insert(recv_key, true);
        let max_entry = self.max_ctr_seen.entry(recv_key).or_insert(0);
        if ctr > *max_entry {
            *max_entry = ctr;
        }

        Ok((media_type, plaintext))
    }

    /// Handle epoch transition
    /// Moves current keys to previous keys, clears current keys, resets counters
    pub fn epoch_transition(&mut self, new_epoch: u8) {
        // Move current keys to previous
        self.previous_keys = self.keys.clone();
        self.previous_keys_timestamp = Some(std::time::Instant::now());

        // Clear current keys, reset counters and replay state
        self.keys.clear();
        for counter in self.counters.values_mut() {
            counter.reset();
        }
        self.max_ctr_seen.clear();
        self.has_received.clear();

        self.epoch = new_epoch;
    }

    /// Clean up old keys after grace period
    pub fn prune_old_keys(&mut self) {
        if let Some(timestamp) = self.previous_keys_timestamp {
            if timestamp.elapsed().as_secs() >= 2 {
                self.previous_keys.clear();
                self.previous_keys_timestamp = None;
            }
        }
    }
}

/// Encode an SFrame header per RFC 9605 §4.3.
///
/// Config byte: |X|  K  |Y|  C  |  (X=1 bit, K=3 bits, Y=1 bit, C=3 bits)
/// Then: extended CTR bytes (if Y=1), then extended KID bytes (if X=1)
pub fn encode_header(ctr: u64, kid: u64) -> Vec<u8> {
    let mut header = Vec::new();

    // Determine KID encoding
    let (x, k_field, kid_ext) = if kid <= 7 {
        (0u8, kid as u8, Vec::new())
    } else {
        let kid_bytes = encode_varint(kid);
        (1u8, (kid_bytes.len() - 1) as u8, kid_bytes)
    };

    // Determine CTR encoding
    let (y, c_field, ctr_ext) = if ctr <= 7 {
        (0u8, ctr as u8, Vec::new())
    } else {
        let ctr_bytes = encode_varint(ctr);
        (1u8, (ctr_bytes.len() - 1) as u8, ctr_bytes)
    };

    let config = (x << 7) | (k_field << 4) | (y << 3) | c_field;
    header.push(config);

    // Extended CTR bytes first (if Y=1), per RFC 9605
    header.extend_from_slice(&ctr_ext);
    // Extended KID bytes second (if X=1)
    header.extend_from_slice(&kid_ext);

    header
}

/// Parse an SFrame header, returning (header_length, ctr, kid).
pub fn parse_header(packet: &[u8]) -> Result<(usize, u64, u64), MeshCallError> {
    if packet.is_empty() {
        return Err(MeshCallError::SFrameDecryption("Empty packet".into()));
    }

    let config = packet[0];
    let x = (config >> 7) & 1;
    let k_field = ((config >> 4) & 0x07) as usize;
    let y = (config >> 3) & 1;
    let c_field = (config & 0x07) as usize;

    let mut offset = 1;

    // Parse CTR first (per RFC 9605 §4.3 wire order)
    let ctr = if y == 0 {
        c_field as u64
    } else {
        let ctr_len = c_field + 1;
        if packet.len() < offset + ctr_len {
            return Err(MeshCallError::SFrameDecryption("Truncated CTR".into()));
        }
        let val = decode_varint(&packet[offset..offset + ctr_len]);
        offset += ctr_len;
        val
    };

    // Parse KID second
    let kid = if x == 0 {
        k_field as u64
    } else {
        let kid_len = k_field + 1;
        if packet.len() < offset + kid_len {
            return Err(MeshCallError::SFrameDecryption("Truncated KID".into()));
        }
        let val = decode_varint(&packet[offset..offset + kid_len]);
        offset += kid_len;
        val
    };

    if packet.len() < offset + NT {
        return Err(MeshCallError::SFrameDecryption("Packet too short".into()));
    }

    Ok((offset, ctr, kid))
}

/// Compute nonce per RFC 9605 §4.4.3: nonce = salt XOR pad(CTR, Nn)
fn compute_nonce(salt: &[u8; NN], ctr: u64) -> [u8; NN] {
    let mut nonce = *salt;
    let ctr_bytes = ctr.to_be_bytes();
    // XOR CTR (8 bytes) into the last 8 bytes of the 12-byte nonce
    for i in 0..8 {
        nonce[NN - 8 + i] ^= ctr_bytes[i];
    }
    nonce
}

/// Encode an integer as minimal big-endian bytes (at least 1 byte).
fn encode_varint(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let skip = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[skip..].to_vec()
}

/// Decode big-endian bytes to u64.
fn decode_varint(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | (b as u64);
    }
    val
}

/// Derive SFrame base key from call base key
///
/// sframe_base_key = HKDF-Expand(call_base_key, "sframe" || media_type || sender_leaf_BE32, 16)
pub fn derive_sframe_base_key(
    call_base_key: &[u8; 32],
    media_type: MediaType,
    sender_leaf: u32,
) -> Result<[u8; 16], MeshCallError> {
    let hkdf = Hkdf::<Sha256>::from_prk(call_base_key)
        .map_err(|_| MeshCallError::KeyDerivation("Invalid PRK".into()))?;

    let mut info = Vec::new();
    info.extend_from_slice(b"sframe");
    info.push(media_type.as_u8());
    info.extend_from_slice(&sender_leaf.to_be_bytes());

    let mut okm = [0u8; 16];
    hkdf.expand(&info, &mut okm)
        .map_err(|e| MeshCallError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;

    Ok(okm)
}

/// Derive SFrame key and salt from base key using RFC 9605 key schedule
///
/// sframe_secret = HKDF-Extract("", sframe_base_key)
/// sframe_key = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret key" || KID_8BE || CS, 16)
/// sframe_salt = HKDF-Expand(sframe_secret, "SFrame 1.0 Secret salt" || KID_8BE || CS, 12)
pub fn derive_sframe_key(
    sframe_base_key: &[u8; 16],
    kid: u64,
) -> Result<SFrameKey, MeshCallError> {
    // Extract with empty salt per RFC 9605 §4.4.2
    let hkdf_extract = Hkdf::<Sha256>::new(Some(&[]), sframe_base_key);

    let kid_bytes = kid.to_be_bytes();
    let cs_bytes = CIPHER_SUITE_AES_128_GCM_SHA256_128.to_be_bytes();

    // Derive key
    let mut key_info = Vec::new();
    key_info.extend_from_slice(b"SFrame 1.0 Secret key");
    key_info.extend_from_slice(&kid_bytes);
    key_info.extend_from_slice(&cs_bytes);

    let mut key = [0u8; NK];
    hkdf_extract.expand(&key_info, &mut key)
        .map_err(|e| MeshCallError::KeyDerivation(format!("Key derivation failed: {}", e)))?;

    // Derive salt
    let mut salt_info = Vec::new();
    salt_info.extend_from_slice(b"SFrame 1.0 Secret salt");
    salt_info.extend_from_slice(&kid_bytes);
    salt_info.extend_from_slice(&cs_bytes);

    let mut salt = [0u8; NN];
    hkdf_extract.expand(&salt_info, &mut salt)
        .map_err(|e| MeshCallError::KeyDerivation(format!("Salt derivation failed: {}", e)))?;

    Ok(SFrameKey { key, salt })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Spec Test Vectors (from MIP-06) ====================

    #[test]
    fn test_sframe_base_key_derivation_spec_vector() {
        // call_base_key from spec
        let call_base_key = hex::decode(
            "a1b2c3d4e5f60718293040506070809011223344556677881a2b3c4d5e6f7080"
        ).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&call_base_key);

        // Audio, leaf 3
        let sframe_base_key = derive_sframe_base_key(&key_array, MediaType::Audio, 3).unwrap();
        assert_eq!(
            hex::encode(sframe_base_key),
            "f7e6b52974ca5061636fe0357f6f005e"
        );

        // Video, leaf 3
        let sframe_base_key_video = derive_sframe_base_key(&key_array, MediaType::Video, 3).unwrap();
        assert_eq!(
            hex::encode(sframe_base_key_video),
            "af1c783f6b62d28b365d4865c41572ec"
        );
    }

    #[test]
    fn test_sframe_key_salt_derivation_spec_vector() {
        // sframe_base_key for audio, leaf 3
        let base_key_hex = "f7e6b52974ca5061636fe0357f6f005e";
        let mut base_key = [0u8; 16];
        base_key.copy_from_slice(&hex::decode(base_key_hex).unwrap());

        // KID for audio, leaf 3, epoch 0 with E=4, S=6 → 0x0030 = 48
        let kid = 48u64;
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        assert_eq!(
            hex::encode(sframe_key.key),
            "65f51bf13b4d4dfd1964358ee0a0c5c3"
        );
        assert_eq!(
            hex::encode(sframe_key.salt),
            "70965b8dd6f1cb2d678c09e2"
        );
    }

    #[test]
    fn test_full_sframe_output_spec_vector() {
        // Full spec test vector: encrypt "Hello Marmot!" and compare output
        let call_base_key = hex::decode(
            "a1b2c3d4e5f60718293040506070809011223344556677881a2b3c4d5e6f7080"
        ).unwrap();
        let mut cbk = [0u8; 32];
        cbk.copy_from_slice(&call_base_key);

        let bits = SFrameBits::default(); // E=4, S=6
        let leaf = 3u32;
        let epoch = 0u8;

        let base_key = derive_sframe_base_key(&cbk, MediaType::Audio, leaf).unwrap();
        let kid = bits.make_kid(MediaType::Audio, leaf, epoch);
        assert_eq!(kid, 0x0030);

        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        let mut ctx = SFrameContext::new(bits, leaf);
        ctx.set_key(MediaType::Audio, sframe_key);

        let plaintext = hex::decode("48656c6c6f204d61726d6f7421").unwrap(); // "Hello Marmot!"
        let frame = ctx.encrypt(MediaType::Audio, &plaintext, &[]).unwrap();

        let expected = hex::decode(
            "80305e16f0a515a9ec79a2d6b0dd9a49f9ea1257c4866ad383a1d2841174ac"
        ).unwrap();
        assert_eq!(hex::encode(&frame), hex::encode(&expected));
    }

    // ==================== Header Encoding/Decoding ====================

    #[test]
    fn test_header_roundtrip() {
        let test_cases = [
            (0u64, 0u64),
            (1, 1),
            (7, 7),
            (0, 8),
            (8, 0),
            (255, 256),
            (0x1234, 0xABCD),
            (0, 0x30),  // KID=48, the spec test vector KID
        ];

        for (ctr, kid) in test_cases {
            let header = encode_header(ctr, kid);
            // Append dummy ciphertext to satisfy parse_header min length check
            let mut packet = header.clone();
            packet.extend_from_slice(&[0u8; 32]);

            let (hlen, parsed_ctr, parsed_kid) = parse_header(&packet).unwrap();
            assert_eq!(hlen, header.len(), "header len mismatch for ctr={ctr} kid={kid}");
            assert_eq!(parsed_ctr, ctr, "ctr mismatch for ctr={ctr} kid={kid}");
            assert_eq!(parsed_kid, kid, "kid mismatch for ctr={ctr} kid={kid}");
        }
    }

    #[test]
    fn test_header_kid_48_ctr_0() {
        // Spec test: KID=48 (0x30), CTR=0
        // KID > 7 → X=1, kid_bytes=[0x30], K=0 (len-1)
        // CTR ≤ 7 → Y=0, C=0
        // Config = (1<<7) | (0<<4) | (0<<3) | 0 = 0x80
        // Header = [0x80, 0x30]
        let header = encode_header(0, 48);
        assert_eq!(header, vec![0x80, 0x30]);
    }

    // ==================== Encrypt/Decrypt ====================

    #[test]
    fn test_sframe_encrypt_decrypt() {
        let bits = SFrameBits::default();
        let mut sender_ctx = SFrameContext::new(bits, 0);
        let mut receiver_ctx = SFrameContext::new(bits, 1); // different leaf for receiver

        let base_key = [0xABu8; 16];
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        sender_ctx.set_key(MediaType::Audio, sframe_key.clone());
        // Receiver needs the sender's key
        receiver_ctx.set_remote_key(MediaType::Audio, 0, 0, sframe_key);

        let plaintext = b"Hello, SFrame!";
        let metadata = b"audio";
        let frame = sender_ctx.encrypt(MediaType::Audio, plaintext, metadata).unwrap();

        let (media_type, decrypted) = receiver_ctx.decrypt(&frame, metadata).unwrap();
        assert_eq!(media_type, MediaType::Audio);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_replay_protection() {
        let bits = SFrameBits::default();
        let mut sender_ctx = SFrameContext::new(bits, 0);
        let mut receiver_ctx = SFrameContext::new(bits, 1);

        let base_key = [0xABu8; 16];
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        sender_ctx.set_key(MediaType::Audio, sframe_key.clone());
        receiver_ctx.set_remote_key(MediaType::Audio, 0, 0, sframe_key);

        let frame0 = sender_ctx.encrypt(MediaType::Audio, b"frame 0", b"").unwrap();
        let frame1 = sender_ctx.encrypt(MediaType::Audio, b"frame 1", b"").unwrap();

        // Decrypt frame1 first (CTR=1)
        receiver_ctx.decrypt(&frame1, b"").unwrap();

        // Replay frame1 → should fail
        assert!(receiver_ctx.decrypt(&frame1, b"").is_err());

        // frame0 has CTR=0 < max_ctr=1 → should also fail
        assert!(receiver_ctx.decrypt(&frame0, b"").is_err());
    }

    #[test]
    fn test_wrong_metadata_fails() {
        let bits = SFrameBits::default();
        let mut sender_ctx = SFrameContext::new(bits, 0);
        let mut receiver_ctx = SFrameContext::new(bits, 1);

        let base_key = [0xABu8; 16];
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        sender_ctx.set_key(MediaType::Audio, sframe_key.clone());
        receiver_ctx.set_remote_key(MediaType::Audio, 0, 0, sframe_key);

        let frame = sender_ctx.encrypt(MediaType::Audio, b"secret", b"audio").unwrap();
        // Different metadata → GCM tag verification fails
        assert!(receiver_ctx.decrypt(&frame, b"video").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let bits = SFrameBits::default();
        let mut sender_ctx = SFrameContext::new(bits, 0);
        let mut receiver_ctx = SFrameContext::new(bits, 1);

        let base_key = [0xABu8; 16];
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

        sender_ctx.set_key(MediaType::Audio, sframe_key.clone());
        receiver_ctx.set_remote_key(MediaType::Audio, 0, 0, sframe_key);

        let mut frame = sender_ctx.encrypt(MediaType::Audio, b"secret", b"").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert!(receiver_ctx.decrypt(&frame, b"").is_err());
    }

    #[test]
    fn test_sframe_counter() {
        let mut counter = SFrameCounter::new();
        assert_eq!(counter.next().unwrap(), 0);
        assert_eq!(counter.next().unwrap(), 1);
        assert_eq!(counter.next().unwrap(), 2);
        assert_eq!(counter.current(), 3);

        counter.reset();
        assert_eq!(counter.current(), 0);
        assert_eq!(counter.next().unwrap(), 0);
    }

    #[test]
    fn test_epoch_transition() {
        let bits = SFrameBits::default();
        let mut ctx = SFrameContext::new(bits, 0);

        let base_key = [0xABu8; 16];
        let kid = bits.make_kid(MediaType::Audio, 0, 0);
        let sframe_key = derive_sframe_key(&base_key, kid).unwrap();
        ctx.set_key(MediaType::Audio, sframe_key);

        let plaintext = b"Before transition";
        let frame = ctx.encrypt(MediaType::Audio, plaintext, b"").unwrap();

        // Epoch transition
        ctx.epoch_transition(1);

        // Set up new key for new epoch
        let new_kid = bits.make_kid(MediaType::Audio, 0, 1);
        let new_sframe_key = derive_sframe_key(&base_key, new_kid).unwrap();
        ctx.set_key(MediaType::Audio, new_sframe_key);

        // Should still be able to decrypt old frame within grace period
        let (media_type, decrypted) = ctx.decrypt(&frame, b"").unwrap();
        assert_eq!(media_type, MediaType::Audio);
        assert_eq!(decrypted, plaintext.to_vec());
    }
}
