//! Byte-level conformance vectors for the agent text stream QUIC feature.
//!
//! These pin the exact bytes promised by `spec/features/agent-text-streams-quic.md`
//! ("Fixed test vectors ... will be published with the conformance fixtures")
//! and the broker control envelope in `spec/transports/quic.md`:
//!
//! - (a) `AgentTextStreamKeyContextV1` canonical encoding;
//! - (b) `record_key` / `nonce_base` HKDF-SHA256 derivation from a fixed
//!   `stream_secret`;
//! - (c) the record AEAD AAD bytes (record wire version `0x01`);
//! - (d) the transcript hash `H_0` and `H_n` with QUIC varint length prefixes;
//! - (e) the binary `QuicBrokerControlEnvelopeV1` encoding.
//!
//! Every expected value below was derived once from the implementation and is
//! asserted literally. A failure here means the wire/derivation bytes changed,
//! which is a spec-visible break.

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamKeyContextV1, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use cgka_traits::{EpochId, GroupId, MemberId, MessageId, SecretBytes};
use transport_quic_broker::{
    QUIC_BROKER_PROTOCOL_V1, QuicBrokerControlEnvelopeV1, QuicBrokerControlTypeV1,
};
use transport_quic_stream::{
    AgentTextStreamCrypto, decrypt_record, derive_record_key, derive_record_nonce, encrypt_record,
    record_aad,
};

/// 32 bytes counting up from `start`.
fn fixed_bytes(start: u8) -> Vec<u8> {
    (0..32_u8).map(|i| start.wrapping_add(i)).collect()
}

fn fixed_group_id() -> Vec<u8> {
    fixed_bytes(0x00)
}

fn fixed_stream_id() -> Vec<u8> {
    fixed_bytes(0x40)
}

fn fixed_sender_id() -> Vec<u8> {
    fixed_bytes(0x80)
}

fn fixed_start_event_id() -> Vec<u8> {
    fixed_bytes(0xc0)
}

/// `stream_secret` fixture: 0x01..=0x20 (the MLS exporter output is opaque
/// 32 bytes; any fixed value pins the HKDF construction).
fn fixed_stream_secret() -> Vec<u8> {
    (1..=32_u8).collect()
}

const FIXED_MLS_EPOCH: u64 = 7;

fn fixed_key_context() -> AgentTextStreamKeyContextV1 {
    AgentTextStreamKeyContextV1::new(
        GroupId::new(fixed_group_id()),
        fixed_stream_id(),
        EpochId(FIXED_MLS_EPOCH),
        MemberId::new(fixed_sender_id()),
        MessageId::new(fixed_start_event_id()),
    )
}

fn fixed_crypto() -> AgentTextStreamCrypto {
    AgentTextStreamCrypto::new(SecretBytes::new(fixed_stream_secret()), fixed_key_context())
}

#[test]
fn vector_key_context_v1_encoding() {
    // struct {
    //   opaque version<1..255>;        // "v1"
    //   opaque group_id<1..1024>;
    //   opaque stream_id<32..32>;
    //   uint64 mls_epoch;
    //   opaque sender_id<1..1024>;
    //   opaque start_event_id<32..32>;
    // } AgentTextStreamKeyContextV1;
    // with QUIC varint length prefixes on every opaque field.
    let encoded = fixed_key_context().encode();
    let expected = concat!(
        "027631",                                                           // len("v1") || "v1"
        "20",                                                               // len(group_id)
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // group_id
        "20",                                                               // len(stream_id)
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", // stream_id
        "0000000000000007",                                                 // mls_epoch u64 be
        "20",                                                               // len(sender_id)
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", // sender_id
        "20",                                                               // len(start_event_id)
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf", // start_event_id
    );
    assert_eq!(hex::encode(&encoded), expected);
}

#[test]
fn vector_record_key_and_nonce_base_derivation() {
    // record_key = HKDF-Expand(stream_secret,
    //   len("record key") || "record key" || key_context, 32)
    // nonce_base = HKDF-Expand(stream_secret,
    //   len("record nonce") || "record nonce" || key_context, 12)
    // HKDF is HKDF-SHA256 with the stream secret used directly as the PRK.
    let crypto = fixed_crypto();
    let record_key = derive_record_key(&crypto).expect("record key derives");
    // seq = 0 XORs nothing into the nonce, so this is nonce_base itself.
    let nonce_base = derive_record_nonce(&crypto, 0).expect("nonce base derives");

    assert_eq!(
        hex::encode(record_key),
        "26145a00159373a22be6fc3cca6882cf44bfc523cf91072153b14f7c912fd413"
    );
    assert_eq!(hex::encode(nonce_base), "5e68a160c5310951c5d0d244");

    // nonce = nonce_base XOR uint96_be(seq): seq 2 flips the low byte.
    let nonce_seq_2 = derive_record_nonce(&crypto, 2).expect("nonce derives");
    let mut expected = nonce_base;
    expected[11] ^= 0x02;
    assert_eq!(nonce_seq_2, expected);
    assert_eq!(hex::encode(nonce_seq_2), "5e68a160c5310951c5d0d246");
}

#[test]
fn vector_record_aad_bytes() {
    // aad = version || SHA-256(group_id) || len(stream_id) || stream_id ||
    //       mls_epoch || len(sender_id) || sender_id || seq || record_type || flags
    // version is the record wire version 0x01 (never the "v1" context text).
    let crypto = fixed_crypto();
    let record = AgentTextStreamRecordV1::new(
        fixed_stream_id(),
        2,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        b"hello".to_vec(),
    );
    let aad = record_aad(&crypto, &record);
    let expected = concat!(
        "01",                                                               // record wire version
        "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", // SHA-256(group_id)
        "20",                                                               // len(stream_id)
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", // stream_id
        "0000000000000007",                                                 // mls_epoch u64 be
        "20",                                                               // len(sender_id)
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", // sender_id
        "0000000000000002",                                                 // seq u64 be
        "01",                                                               // record_type TextDelta
        "00",                                                               // flags
    );
    assert_eq!(hex::encode(&aad), expected);
}

#[test]
fn vector_record_encryption_chacha20poly1305() {
    // ct = AEAD_Encrypt(record_key, nonce_base XOR uint96_be(seq), aad, frame)
    // for the same fixed record as the AAD vector (seq 2, TextDelta "hello").
    let crypto = fixed_crypto();
    let record = AgentTextStreamRecordV1::new(
        fixed_stream_id(),
        2,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        b"hello".to_vec(),
    );
    let sealed = encrypt_record(&crypto, &record).expect("record encrypts");
    assert_eq!(
        hex::encode(&sealed.plaintext_frame),
        "4c5c6b73cb46be099954b0159a99eec699aad08a2b"
    );
    assert_eq!(
        sealed.plaintext_frame.len(),
        record.plaintext_frame.len() + 16,
        "ciphertext is plaintext plus the 16-byte AEAD tag"
    );
    let opened = decrypt_record(&crypto, &sealed).expect("record decrypts");
    assert_eq!(opened, record);
}

#[test]
fn vector_transcript_hash_h0_and_hn() {
    // H_0 = SHA-256("marmot agent text stream transcript v1" ||
    //               len(stream_id) || stream_id ||
    //               len(start_event_id) || start_event_id)
    // H_n = SHA-256(H_{n-1} || seq || record_type || plaintext_frame)
    // with QUIC varint length prefixes (a 32-byte id's prefix is 0x20).
    let mut transcript =
        AgentTextStreamTranscriptV1::new(fixed_stream_id(), MessageId::new(fixed_start_event_id()));
    assert_eq!(
        hex::encode(transcript.hash()),
        "e4ef961892a7425c1c279f747920ac18d55810732f2aa6b20b330f2666714c78"
    );

    transcript.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hello");
    assert_eq!(
        hex::encode(transcript.hash()),
        "ef0101a5f727105f68a8eb339178cfdf8b8a822a9b34183daed2091da6acabc5"
    );

    // Status records consume a seq and contribute to the transcript too.
    transcript.append(2, AGENT_TEXT_STREAM_RECORD_STATUS, b"thinking");
    assert_eq!(
        hex::encode(transcript.hash()),
        "c0bc23a83a5607f29babfd40464c454306674b82b4653c88fd6f8dbb77e1415c"
    );
    assert_eq!(transcript.chunk_count(), 2);
}

#[test]
fn vector_broker_control_envelope_encoding() {
    // struct {
    //   opaque marmot_broker<1..255>;     // ASCII "marmot.quic_broker.v1"
    //   BrokerControlType control_type;   // uint8: publish(1), subscribe(2)
    //   opaque stream_id<1..64>;          // raw bytes
    //   opaque start_event_id<1..64>;     // raw bytes
    // } QuicBrokerControlEnvelopeV1;
    let start_event_id = MessageId::new(fixed_start_event_id());
    let publish = QuicBrokerControlEnvelopeV1::publish(fixed_stream_id(), &start_event_id);
    let encoded = publish.encode().expect("publish envelope encodes");
    let expected = concat!(
        "15",                                                               // len(marmot_broker) = 21
        "6d61726d6f742e717569635f62726f6b65722e7631", // "marmot.quic_broker.v1"
        "01",                                         // control_type publish
        "20",                                         // len(stream_id)
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", // stream_id
        "20",                                         // len(start_event_id)
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf", // start_event_id
    );
    assert_eq!(hex::encode(&encoded), expected);
    assert_eq!(
        hex::encode(QUIC_BROKER_PROTOCOL_V1.as_bytes()),
        "6d61726d6f742e717569635f62726f6b65722e7631"
    );
    let decoded = QuicBrokerControlEnvelopeV1::decode(&encoded).expect("publish decodes");
    assert_eq!(decoded, publish);
    assert_eq!(decoded.control_type, QuicBrokerControlTypeV1::Publish);

    let subscribe = QuicBrokerControlEnvelopeV1::subscribe(fixed_stream_id(), &start_event_id);
    let encoded = subscribe.encode().expect("subscribe envelope encodes");
    // Identical to the publish envelope except control_type = 2.
    let expected = expected.replacen(
        "6d61726d6f742e717569635f62726f6b65722e763101",
        "6d61726d6f742e717569635f62726f6b65722e763102",
        1,
    );
    assert_eq!(hex::encode(&encoded), expected);
    assert_eq!(
        QuicBrokerControlEnvelopeV1::decode(&encoded).expect("subscribe decodes"),
        subscribe
    );
}
