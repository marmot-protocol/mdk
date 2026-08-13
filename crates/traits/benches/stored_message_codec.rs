use cgka_traits::message::StoredMessagePayload;
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{MemberId, MessageId};
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

fn representative_welcome() -> StoredMessagePayload {
    StoredMessagePayload::outbound_welcome(TransportMessage {
        id: MessageId::new(vec![0x11; 32]),
        payload: vec![0xA5; 16_727],
        timestamp: Timestamp(1_723_456_789),
        causal_deps: Vec::new(),
        source: TransportSource("nostr".to_owned()),
        envelope: TransportEnvelope::Welcome {
            recipient: MemberId::new(vec![0x22; 32]),
        },
    })
}

fn codecs(c: &mut Criterion) {
    let value = representative_welcome();
    let json = serde_json::to_vec(&value).unwrap();
    let mdk = value.encode().unwrap();
    eprintln!(
        "stored_message_codec sizes raw_payload=16727 json={} mdk_v2={}",
        json.len(),
        mdk.len()
    );

    let mut group = c.benchmark_group("stored_message_codec");
    group.throughput(Throughput::Bytes(16_727));
    group.bench_function("encode/json", |b| {
        b.iter(|| serde_json::to_vec(black_box(&value)).unwrap())
    });
    group.bench_function("encode/mdk_v2", |b| {
        b.iter(|| black_box(&value).encode().unwrap())
    });
    group.bench_function("decode/json", |b| {
        b.iter(|| serde_json::from_slice::<StoredMessagePayload>(black_box(&json)).unwrap())
    });
    group.bench_function("decode/mdk_v2", |b| {
        b.iter(|| StoredMessagePayload::decode(black_box(&mdk)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, codecs);
criterion_main!(benches);
