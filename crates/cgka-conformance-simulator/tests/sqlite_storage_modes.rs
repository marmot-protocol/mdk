use cgka_conformance_simulator::{ClientBuilder, HarnessStorageMode, TransportBus};

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

#[tokio::test]
async fn harness_can_use_temp_file_backed_sqlite_storage() {
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .storage_mode(HarnessStorageMode::TempFileBackedSqlite)
        .attach(&bus);
    let member_id = alice.member_id();

    let key_package = alice.fresh_key_package().await;
    assert!(!key_package.bytes().is_empty());

    alice.restart();
    assert_eq!(alice.member_id(), member_id);
}
