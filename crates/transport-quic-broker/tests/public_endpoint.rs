use std::net::SocketAddr;
use std::time::Duration;

use cgka_traits::MessageId;
use tokio::time::{sleep, timeout};
use transport_quic_broker::{
    BrokerServerTrust, PublishTextToBroker, SubscribeTextFromBroker, publish_text_to_broker,
    subscribe_text_from_broker,
};

const PUBLIC_BROKER_AUTHORITY: &str = "quic-broker.ipf.dev:4450";
const PUBLIC_BROKER_SERVER_NAME: &str = "quic-broker.ipf.dev";

#[tokio::test]
#[ignore = "hits the public QUIC broker endpoint"]
async fn public_quic_broker_round_trips_direct_publish_and_subscribe() {
    let addrs = timeout(Duration::from_secs(10), async {
        tokio::net::lookup_host(PUBLIC_BROKER_AUTHORITY)
            .await
            .map(|addrs| addrs.collect::<Vec<_>>())
    })
    .await
    .expect("public broker DNS lookup should not hang")
    .expect("public broker DNS lookup should succeed");
    assert!(
        !addrs.is_empty(),
        "public broker DNS lookup returned no addresses"
    );

    let mut last_error = None;
    for broker_addr in addrs {
        eprintln!("trying public QUIC broker address {broker_addr}");
        match timeout(
            Duration::from_secs(25),
            round_trip_public_broker_addr(broker_addr),
        )
        .await
        {
            Ok(Ok(())) => return,
            Ok(Err(err)) => last_error = Some(err),
            Err(_) => last_error = Some(format!("round trip to {broker_addr} timed out")),
        }
    }

    panic!(
        "public broker round trip failed for every resolved address: {}",
        last_error.unwrap_or_else(|| "no addresses attempted".to_owned())
    );
}

async fn round_trip_public_broker_addr(broker_addr: SocketAddr) -> Result<(), String> {
    let stream_id = transport_quic_stream::random_stream_id();
    let start_event_id = MessageId::new(vec![0x55; 32]);
    let text = format!(
        "public quic broker round trip {}",
        hex::encode(&stream_id[..4])
    );
    let subscriber_stream_id = stream_id.clone();
    let subscriber_start_event_id = start_event_id.clone();
    let subscriber = tokio::spawn(async move {
        subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: PUBLIC_BROKER_SERVER_NAME.to_owned(),
            trust: BrokerServerTrust::Platform,
            stream_id: subscriber_stream_id,
            start_event_id: subscriber_start_event_id,
            crypto: None,
        })
        .await
    });

    sleep(Duration::from_millis(250)).await;

    let sent = publish_text_to_broker(PublishTextToBroker {
        broker_addr,
        server_name: PUBLIC_BROKER_SERVER_NAME.to_owned(),
        trust: BrokerServerTrust::Platform,
        stream_id: stream_id.clone(),
        start_event_id,
        text: text.clone(),
        max_chunk_bytes: 1024,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .map_err(|err| format!("publish to {broker_addr} failed: {err}"))?;
    let received = timeout(Duration::from_secs(20), subscriber)
        .await
        .map_err(|_| format!("subscribe from {broker_addr} timed out"))?
        .map_err(|err| format!("subscriber task failed: {err}"))?
        .map_err(|err| format!("subscribe from {broker_addr} failed: {err}"))?;

    if received.stream_id != stream_id {
        return Err(format!(
            "subscriber returned wrong stream id from {broker_addr}"
        ));
    }
    if received.text != text {
        return Err(format!(
            "subscriber text mismatch from {broker_addr}: expected {text:?}, got {:?}",
            received.text
        ));
    }
    if received.transcript_hash != sent.transcript_hash {
        return Err(format!("transcript hash mismatch from {broker_addr}"));
    }
    Ok(())
}
