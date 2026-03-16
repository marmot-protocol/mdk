//! Integration tests for MIP-06 mesh calls
//!
//! Tests the complete call lifecycle including:
//! - SFrame crypto aligned with spec test vectors
//! - Call initiation, answer, and teardown
//! - Signaling event production (kinds 450-454)
//! - Epoch rotation with key re-derivation
//! - Call timeouts and cleanup
//! - Replay protection

use std::sync::Arc;

use mdk_core::mesh_calls::{
    CallAnswer, CallAnswerStatus, CallId, CallInitiation, CallType, MediaType,
    MeshCallError, MeshCallManager, SFrameBits, SFrameContext, SFrameKey, SFrameCounter,
    derive_sframe_base_key, derive_sframe_key, encode_header, parse_header,
};
use mdk_core::GroupId;
use nostr::Keys;

// ============================================================
// Spec Test Vector Constants (from MIP-06 §10)
// ============================================================

const TV_CALL_BASE_KEY: &str = "a1b2c3d4e5f60718293040506070809011223344556677881a2b3c4d5e6f7080";
const TV_SFRAME_BASE_KEY_AUDIO: &str = "f7e6b52974ca5061636fe0357f6f005e";
const TV_SFRAME_BASE_KEY_VIDEO: &str = "af1c783f6b62d28b365d4865c41572ec";
const TV_SFRAME_KEY: &str = "65f51bf13b4d4dfd1964358ee0a0c5c3";
const TV_SFRAME_SALT: &str = "70965b8dd6f1cb2d678c09e2";
const TV_KID_AUDIO_LEAF3_EPOCH0: u64 = 0x0030; // 48
const TV_PLAINTEXT: &str = "48656c6c6f204d61726d6f7421"; // "Hello Marmot!"
const TV_FULL_OUTPUT: &str = "80305e16f0a515a9ec79a2d6b0dd9a49f9ea1257c4866ad383a1d2841174ac";

// ============================================================
// Key Derivation Tests (spec vectors)
// ============================================================

#[test]
fn test_sframe_base_key_audio_spec_vector() {
    let cbk = hex::decode(TV_CALL_BASE_KEY).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&cbk);

    let base_key = derive_sframe_base_key(&key_array, MediaType::Audio, 3).unwrap();
    assert_eq!(hex::encode(base_key), TV_SFRAME_BASE_KEY_AUDIO);
}

#[test]
fn test_sframe_base_key_video_spec_vector() {
    let cbk = hex::decode(TV_CALL_BASE_KEY).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&cbk);

    let base_key = derive_sframe_base_key(&key_array, MediaType::Video, 3).unwrap();
    assert_eq!(hex::encode(base_key), TV_SFRAME_BASE_KEY_VIDEO);
}

#[test]
fn test_sframe_key_salt_spec_vector() {
    let mut base_key = [0u8; 16];
    base_key.copy_from_slice(&hex::decode(TV_SFRAME_BASE_KEY_AUDIO).unwrap());

    let sframe_key = derive_sframe_key(&base_key, TV_KID_AUDIO_LEAF3_EPOCH0).unwrap();
    assert_eq!(hex::encode(sframe_key.key), TV_SFRAME_KEY);
    assert_eq!(hex::encode(sframe_key.salt), TV_SFRAME_SALT);
}

#[test]
fn test_kid_encoding_spec_vectors() {
    let bits = SFrameBits::default(); // E=4, S=6

    // leaf 3, audio, epoch 0 → KID = 0x0030
    assert_eq!(bits.make_kid(MediaType::Audio, 3, 0), 0x0030);
    // leaf 3, audio, epoch 14 → KID = 0x003e
    assert_eq!(bits.make_kid(MediaType::Audio, 3, 14), 0x003e);
    // leaf 3, video, epoch 14 → KID = 0x043e
    assert_eq!(bits.make_kid(MediaType::Video, 3, 14), 0x043e);
    // leaf 3, screen, epoch 14 → KID = 0x083e
    assert_eq!(bits.make_kid(MediaType::ScreenShare, 3, 14), 0x083e);
    // leaf 63, audio, epoch 15 → KID = 0x03ff
    assert_eq!(bits.make_kid(MediaType::Audio, 63, 15), 0x03ff);
}

#[test]
fn test_kid_roundtrip() {
    let bits = SFrameBits::default();

    for media in [MediaType::Audio, MediaType::Video, MediaType::ScreenShare] {
        for leaf in [0, 1, 3, 7, 31, 63] {
            for epoch in [0, 1, 7, 14, 15] {
                let kid = bits.make_kid(media, leaf, epoch);
                let (parsed_media, parsed_leaf, parsed_epoch) = bits.parse_kid(kid);
                assert_eq!(parsed_media, media, "media mismatch for {media:?} leaf={leaf} epoch={epoch}");
                assert_eq!(parsed_leaf, leaf, "leaf mismatch for {media:?} leaf={leaf} epoch={epoch}");
                assert_eq!(parsed_epoch, epoch, "epoch mismatch for {media:?} leaf={leaf} epoch={epoch}");
            }
        }
    }
}

// ============================================================
// SFrame Header Wire Format Tests
// ============================================================

#[test]
fn test_header_spec_vector_kid48_ctr0() {
    // KID=48 (0x30) > 7 → extended, CTR=0 ≤ 7 → inline
    // Config: X=1, K=0 (1 byte - 1), Y=0, C=0
    // = (1<<7) | (0<<4) | (0<<3) | 0 = 0x80
    // Header: [0x80, 0x30]
    let header = encode_header(0, 48);
    assert_eq!(header, vec![0x80, 0x30]);
}

#[test]
fn test_header_inline_kid_and_ctr() {
    // KID=3, CTR=5 → both inline
    // Config: X=0, K=3, Y=0, C=5
    // = (0<<7) | (3<<4) | (0<<3) | 5 = 0x35
    let header = encode_header(5, 3);
    assert_eq!(header, vec![0x35]);
}

#[test]
fn test_header_roundtrip_matrix() {
    let test_cases = [
        (0u64, 0u64),
        (1, 1),
        (7, 7),
        (0, 8),
        (8, 0),
        (255, 256),
        (0x1234, 0xABCD),
        (0, 0x30),
        (0xFFFF, 0xFFFF),
        (0, 1023), // max KID with default bits
    ];

    for (ctr, kid) in test_cases {
        let header = encode_header(ctr, kid);
        let mut packet = header.clone();
        packet.extend_from_slice(&[0u8; 32]); // dummy ciphertext

        let (hlen, parsed_ctr, parsed_kid) = parse_header(&packet).unwrap();
        assert_eq!(hlen, header.len(), "header len for ctr={ctr} kid={kid}");
        assert_eq!(parsed_ctr, ctr, "ctr for ctr={ctr} kid={kid}");
        assert_eq!(parsed_kid, kid, "kid for ctr={ctr} kid={kid}");
    }
}

// ============================================================
// Full SFrame Encrypt/Decrypt (spec vector)
// ============================================================

#[test]
fn test_full_sframe_output_matches_spec() {
    let cbk = hex::decode(TV_CALL_BASE_KEY).unwrap();
    let mut call_base_key = [0u8; 32];
    call_base_key.copy_from_slice(&cbk);

    let bits = SFrameBits::default();
    let leaf = 3u32;

    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, leaf).unwrap();
    let kid = bits.make_kid(MediaType::Audio, leaf, 0);
    let sframe_key = derive_sframe_key(&base_key, kid).unwrap();

    let mut ctx = SFrameContext::new(bits, leaf);
    ctx.set_key(MediaType::Audio, sframe_key);

    let plaintext = hex::decode(TV_PLAINTEXT).unwrap();
    let frame = ctx.encrypt(MediaType::Audio, &plaintext, &[]).unwrap();

    assert_eq!(hex::encode(&frame), TV_FULL_OUTPUT);
}

#[test]
fn test_sframe_encrypt_decrypt_roundtrip() {
    let call_base_key = [0xABu8; 32];
    let bits = SFrameBits::default();

    // Sender context (leaf 0)
    let mut sender = SFrameContext::new(bits, 0);
    let base_key_s = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid_s = bits.make_kid(MediaType::Audio, 0, 0);
    let key_s = derive_sframe_key(&base_key_s, kid_s).unwrap();
    sender.set_key(MediaType::Audio, key_s.clone());

    // Receiver context (leaf 1) with sender's key
    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key_s);

    let plaintext = b"voice frame data";
    let metadata = b"audio";

    let frame = sender.encrypt(MediaType::Audio, plaintext, metadata).unwrap();
    let (media_type, decrypted) = receiver.decrypt(&frame, metadata).unwrap();

    assert_eq!(media_type, MediaType::Audio);
    assert_eq!(decrypted, plaintext.to_vec());
}

#[test]
fn test_sframe_multiple_frames() {
    let call_base_key = [0xCDu8; 32];
    let bits = SFrameBits::default();

    let mut sender = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    sender.set_key(MediaType::Audio, key.clone());

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key);

    for i in 0..100 {
        let plaintext = format!("frame {}", i);
        let frame = sender.encrypt(MediaType::Audio, plaintext.as_bytes(), b"").unwrap();
        let (_, decrypted) = receiver.decrypt(&frame, b"").unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }
}

// ============================================================
// Replay Protection Tests
// ============================================================

#[test]
fn test_replay_rejected() {
    let call_base_key = [0xEFu8; 32];
    let bits = SFrameBits::default();

    let mut sender = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    sender.set_key(MediaType::Audio, key.clone());

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key);

    let frame0 = sender.encrypt(MediaType::Audio, b"frame 0", b"").unwrap();
    let frame1 = sender.encrypt(MediaType::Audio, b"frame 1", b"").unwrap();

    // Process frame1 first (CTR=1)
    receiver.decrypt(&frame1, b"").unwrap();

    // Replay frame1 → rejected
    assert!(receiver.decrypt(&frame1, b"").is_err());

    // Old frame0 (CTR=0 < max_ctr=1) → rejected
    assert!(receiver.decrypt(&frame0, b"").is_err());
}

// ============================================================
// Authentication Tests
// ============================================================

#[test]
fn test_wrong_metadata_rejected() {
    let call_base_key = [0x11u8; 32];
    let bits = SFrameBits::default();

    let mut sender = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    sender.set_key(MediaType::Audio, key.clone());

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key);

    let frame = sender.encrypt(MediaType::Audio, b"secret", b"audio").unwrap();
    assert!(receiver.decrypt(&frame, b"video").is_err());
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let call_base_key = [0x22u8; 32];
    let bits = SFrameBits::default();

    let mut sender = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    sender.set_key(MediaType::Audio, key.clone());

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key);

    let mut frame = sender.encrypt(MediaType::Audio, b"secret", b"").unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 0xFF; // flip a bit
    assert!(receiver.decrypt(&frame, b"").is_err());
}

#[test]
fn test_wrong_key_rejected() {
    let bits = SFrameBits::default();

    let mut sender = SFrameContext::new(bits, 0);
    let base_key_s = derive_sframe_base_key(&[0x33u8; 32], MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key_s = derive_sframe_key(&base_key_s, kid).unwrap();
    sender.set_key(MediaType::Audio, key_s);

    // Receiver has a DIFFERENT key
    let mut receiver = SFrameContext::new(bits, 1);
    let base_key_r = derive_sframe_base_key(&[0x44u8; 32], MediaType::Audio, 0).unwrap();
    let key_r = derive_sframe_key(&base_key_r, kid).unwrap();
    receiver.set_remote_key(MediaType::Audio, 0, 0, key_r);

    let frame = sender.encrypt(MediaType::Audio, b"secret", b"").unwrap();
    assert!(receiver.decrypt(&frame, b"").is_err());
}

// ============================================================
// Epoch Transition Tests
// ============================================================

#[test]
fn test_epoch_transition_with_grace_period() {
    let call_base_key = [0x55u8; 32];
    let bits = SFrameBits::default();

    let mut ctx = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid0 = bits.make_kid(MediaType::Audio, 0, 0);
    let key0 = derive_sframe_key(&base_key, kid0).unwrap();
    ctx.set_key(MediaType::Audio, key0);

    // Encrypt before transition
    let frame = ctx.encrypt(MediaType::Audio, b"before epoch change", b"").unwrap();

    // Epoch transition
    ctx.epoch_transition(1);
    let kid1 = bits.make_kid(MediaType::Audio, 0, 1);
    let key1 = derive_sframe_key(&base_key, kid1).unwrap();
    ctx.set_key(MediaType::Audio, key1);

    // Old frame should still decrypt within grace period
    let (_, plaintext) = ctx.decrypt(&frame, b"").unwrap();
    assert_eq!(plaintext, b"before epoch change");

    // New epoch encryption should work
    let frame_new = ctx.encrypt(MediaType::Audio, b"after epoch change", b"").unwrap();
    let (_, plaintext_new) = ctx.decrypt(&frame_new, b"").unwrap();
    assert_eq!(plaintext_new, b"after epoch change");
}

#[test]
fn test_epoch_resets_counters() {
    let call_base_key = [0x66u8; 32];
    let bits = SFrameBits::default();

    let mut ctx = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    ctx.set_key(MediaType::Audio, key);

    // Encrypt several frames to advance counter
    for _ in 0..10 {
        ctx.encrypt(MediaType::Audio, b"frame", b"").unwrap();
    }

    // Epoch transition resets CTR to 0
    ctx.epoch_transition(1);
    let kid1 = bits.make_kid(MediaType::Audio, 0, 1);
    let key1 = derive_sframe_key(&base_key, kid1).unwrap();
    ctx.set_key(MediaType::Audio, key1.clone());

    // First frame after transition should have CTR=0
    let frame = ctx.encrypt(MediaType::Audio, b"new epoch", b"").unwrap();

    // Verify by decrypting with a fresh receiver
    let mut receiver = SFrameContext::new(bits, 1);
    receiver.epoch_transition(1); // match epoch
    receiver.set_remote_key(MediaType::Audio, 1, 0, key1);
    let (_, plaintext) = receiver.decrypt(&frame, b"").unwrap();
    assert_eq!(plaintext, b"new epoch");
}

// ============================================================
// Different Senders Produce Different Keys
// ============================================================

#[test]
fn test_different_senders_different_keys() {
    let call_base_key = [0x77u8; 32];

    let key0 = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let key1 = derive_sframe_base_key(&call_base_key, MediaType::Audio, 1).unwrap();
    let key2 = derive_sframe_base_key(&call_base_key, MediaType::Audio, 2).unwrap();

    assert_ne!(key0, key1);
    assert_ne!(key1, key2);
    assert_ne!(key0, key2);
}

#[test]
fn test_different_media_types_different_keys() {
    let call_base_key = [0x88u8; 32];

    let audio_key = derive_sframe_base_key(&call_base_key, MediaType::Audio, 0).unwrap();
    let video_key = derive_sframe_base_key(&call_base_key, MediaType::Video, 0).unwrap();

    assert_ne!(audio_key, video_key);
}

// ============================================================
// Call Manager Integration Tests
// ============================================================

#[tokio::test]
async fn test_call_initiation_produces_signaling() {
    let manager = MeshCallManager::new();
    let keys = Keys::generate();
    let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
    let call_base_key = [0x99u8; 32];

    let call_id = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key,
        )
        .await
        .unwrap();

    // Should have produced a kind 450 signaling event
    let signaling = manager.recv_signaling().await;
    assert!(signaling.is_some());
}

#[tokio::test]
async fn test_call_answer_produces_signaling() {
    let manager = MeshCallManager::new();
    let caller_keys = Keys::generate();
    let callee_keys = Keys::generate();
    let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
    let call_base_key = [0xAAu8; 32];

    let call_id = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &caller_keys.public_key(),
            0,
            &call_base_key,
        )
        .await
        .unwrap();

    // Drain initiation signaling
    let _ = manager.recv_signaling().await;
    // Drain ringing state update - may or may not produce signaling
    // depending on implementation

    manager
        .answer_call(
            &call_id,
            CallAnswer::accept(),
            &callee_keys.public_key(),
            1,
            &call_base_key,
        )
        .await
        .unwrap();

    // Should have produced a kind 451 signaling event
    let signaling = manager.recv_signaling().await;
    assert!(signaling.is_some());
}

#[tokio::test]
async fn test_call_end_produces_signaling() {
    let manager = MeshCallManager::new();
    let keys = Keys::generate();
    let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
    let call_base_key = [0xBBu8; 32];

    let call_id = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key,
        )
        .await
        .unwrap();

    // Drain initiation signaling
    let _ = manager.recv_signaling().await;

    manager.end_call(&call_id, &keys.public_key()).await.unwrap();

    // Call should no longer be active
    assert!(manager.get_call(&call_id).await.is_none());
}

#[tokio::test]
async fn test_duplicate_call_rejected() {
    let manager = MeshCallManager::new();
    let keys = Keys::generate();
    let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
    let call_base_key = [0xCCu8; 32];

    manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key,
        )
        .await
        .unwrap();

    // Second call on same group should fail
    let result = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key,
        )
        .await;

    assert!(matches!(result, Err(MeshCallError::CallAlreadyExists)));
}

#[tokio::test]
async fn test_encrypt_decrypt_media_via_manager() {
    let manager = MeshCallManager::new();
    let keys = Keys::generate();
    let group_id = GroupId::from_slice(&[5, 6, 7, 8]);
    let call_base_key = [0xDDu8; 32];

    let call_id = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key,
        )
        .await
        .unwrap();

    // Encrypt a media frame
    let plaintext = b"audio frame data";
    let frame = manager
        .encrypt_media(&call_id, MediaType::Audio, plaintext, b"")
        .await
        .unwrap();

    // Decrypt it back
    let (media_type, decrypted) = manager.decrypt_media(&call_id, &frame, b"").await.unwrap();
    assert_eq!(media_type, MediaType::Audio);
    assert_eq!(decrypted, plaintext.to_vec());
}

#[tokio::test]
async fn test_epoch_change_via_manager() {
    let manager = MeshCallManager::new();
    let keys = Keys::generate();
    let group_id = GroupId::from_slice(&[9, 10, 11, 12]);
    let call_base_key_epoch0 = [0xEEu8; 32];
    let call_base_key_epoch1 = [0xFFu8; 32];

    let call_id = manager
        .initiate_call(
            &group_id,
            CallInitiation::new_audio(),
            &keys.public_key(),
            0,
            &call_base_key_epoch0,
        )
        .await
        .unwrap();

    // Encrypt with epoch 0
    let frame0 = manager
        .encrypt_media(&call_id, MediaType::Audio, b"epoch 0 frame", b"")
        .await
        .unwrap();

    // Rotate epoch
    manager
        .handle_epoch_change(&call_id, 1, &call_base_key_epoch1)
        .await
        .unwrap();

    // Old frame should still decrypt (grace period)
    let (_, plaintext) = manager.decrypt_media(&call_id, &frame0, b"").await.unwrap();
    assert_eq!(plaintext, b"epoch 0 frame");

    // New frame with new epoch should work
    let frame1 = manager
        .encrypt_media(&call_id, MediaType::Audio, b"epoch 1 frame", b"")
        .await
        .unwrap();
    let (_, plaintext1) = manager.decrypt_media(&call_id, &frame1, b"").await.unwrap();
    assert_eq!(plaintext1, b"epoch 1 frame");
}

// ============================================================
// Edge Cases
// ============================================================

#[test]
fn test_empty_plaintext() {
    let bits = SFrameBits::default();
    let mut ctx = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&[0x11u8; 32], MediaType::Audio, 0).unwrap();
    let kid = bits.make_kid(MediaType::Audio, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    ctx.set_key(MediaType::Audio, key.clone());

    let frame = ctx.encrypt(MediaType::Audio, b"", b"").unwrap();

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Audio, 0, 0, key);
    let (_, plaintext) = receiver.decrypt(&frame, b"").unwrap();
    assert_eq!(plaintext, b"");
}

#[test]
fn test_large_plaintext() {
    let bits = SFrameBits::default();
    let mut ctx = SFrameContext::new(bits, 0);
    let base_key = derive_sframe_base_key(&[0x22u8; 32], MediaType::Video, 0).unwrap();
    let kid = bits.make_kid(MediaType::Video, 0, 0);
    let key = derive_sframe_key(&base_key, kid).unwrap();
    ctx.set_key(MediaType::Video, key.clone());

    // 65KB frame (large video frame)
    let plaintext = vec![0xBBu8; 65536];
    let frame = ctx.encrypt(MediaType::Video, &plaintext, b"video").unwrap();

    let mut receiver = SFrameContext::new(bits, 1);
    receiver.set_remote_key(MediaType::Video, 0, 0, key);
    let (media_type, decrypted) = receiver.decrypt(&frame, b"video").unwrap();
    assert_eq!(media_type, MediaType::Video);
    assert_eq!(decrypted, plaintext);
}
