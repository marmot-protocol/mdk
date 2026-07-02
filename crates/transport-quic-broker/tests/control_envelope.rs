use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN;
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, QUIC_BROKER_CONTROL_PUBLISH,
    QUIC_BROKER_CONTROL_SUBSCRIBE, QUIC_BROKER_PROTOCOL_V1, QuicBrokerControlEnvelopeV1,
    QuicBrokerControlTypeV1, QuicBrokerError, publish_text_to_broker,
};

#[tokio::test]
async fn insecure_local_rejects_remote_broker_addr() {
    let err = publish_text_to_broker(PublishTextToBroker {
        broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4450),
        server_name: "example.com".to_owned(),
        trust: BrokerServerTrust::InsecureLocal,
        stream_id: vec![0xaa; 32],
        start_event_id: MessageId::new(vec![0x11; 32]),
        text: "hello".to_owned(),
        max_chunk_bytes: 5,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        QuicBrokerError::InsecureLocalRequiresLoopback(_)
    ));
}

#[test]
fn broker_control_envelope_round_trips_binary_encoding() {
    let stream_id = vec![0xaa; 32];
    let start_event_id = MessageId::new(vec![0x11; 32]);

    let publish = QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id);
    let bytes = publish.encode().unwrap();
    // opaque marmot_broker<1..255>: single-byte varint prefix (21) + ASCII.
    assert_eq!(bytes[0], 21);
    assert_eq!(&bytes[1..22], QUIC_BROKER_PROTOCOL_V1.as_bytes());
    assert_eq!(bytes[22], QUIC_BROKER_CONTROL_PUBLISH);
    // opaque stream_id<1..64>: raw bytes, not hex text.
    assert_eq!(bytes[23], 32);
    assert_eq!(&bytes[24..56], stream_id.as_slice());
    assert_eq!(bytes[56], 32);
    assert_eq!(&bytes[57..89], start_event_id.as_slice());
    assert_eq!(bytes.len(), 89);
    assert_eq!(
        QuicBrokerControlEnvelopeV1::decode(&bytes).unwrap(),
        publish
    );

    let subscribe = QuicBrokerControlEnvelopeV1::subscribe(stream_id, &start_event_id);
    let bytes = subscribe.encode().unwrap();
    assert_eq!(bytes[22], QUIC_BROKER_CONTROL_SUBSCRIBE);
    assert_eq!(
        QuicBrokerControlEnvelopeV1::decode(&bytes).unwrap(),
        subscribe
    );
}

#[test]
fn broker_control_envelope_rejects_malformed_envelopes() {
    let valid =
        QuicBrokerControlEnvelopeV1::publish(vec![0xaa; 32], &MessageId::new(vec![0x11; 32]))
            .encode()
            .unwrap();

    let mut wrong_protocol = valid.clone();
    wrong_protocol[1] = b'x';
    assert!(matches!(
        QuicBrokerControlEnvelopeV1::decode(&wrong_protocol),
        Err(QuicBrokerError::WrongControlProtocol(_))
    ));

    let mut unknown_type = valid.clone();
    unknown_type[22] = 3;
    assert!(matches!(
        QuicBrokerControlEnvelopeV1::decode(&unknown_type),
        Err(QuicBrokerError::UnknownControlType(3))
    ));

    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(matches!(
        QuicBrokerControlEnvelopeV1::decode(&trailing),
        Err(QuicBrokerError::ControlTrailingBytes(1))
    ));

    assert!(matches!(
        QuicBrokerControlEnvelopeV1::decode(&valid[..10]),
        Err(QuicBrokerError::ControlTruncated(_))
    ));

    let empty_stream_id = QuicBrokerControlEnvelopeV1 {
        control_type: QuicBrokerControlTypeV1::Publish,
        stream_id: Vec::new(),
        start_event_id: vec![0x11; 32],
    };
    assert!(matches!(
        empty_stream_id.encode(),
        Err(QuicBrokerError::EmptyStreamId)
    ));

    let oversized_stream_id = QuicBrokerControlEnvelopeV1 {
        control_type: QuicBrokerControlTypeV1::Publish,
        stream_id: vec![0xaa; AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1],
        start_event_id: vec![0x11; 32],
    };
    assert!(matches!(
        oversized_stream_id.encode(),
        Err(QuicBrokerError::StreamIdTooLong(len))
            if len == AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1
    ));

    let oversized_start_event_id = QuicBrokerControlEnvelopeV1 {
        control_type: QuicBrokerControlTypeV1::Publish,
        stream_id: vec![0xaa; 32],
        start_event_id: vec![0x11; AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1],
    };
    assert!(matches!(
        oversized_start_event_id.encode(),
        Err(QuicBrokerError::StartEventIdTooLong(len))
            if len == AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1
    ));
}
