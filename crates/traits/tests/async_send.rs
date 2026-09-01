#![cfg(not(target_arch = "wasm32"))]

use cgka_traits::engine::CgkaEngine;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::TransportMessage;
use cgka_traits::transport_adapter::TransportAdapter;

fn assert_send<T: Send>(_: T) {}

#[test]
fn native_async_trait_futures_are_send() {
    fn assert_trait_futures(
        engine: &mut dyn CgkaEngine,
        peeler: &dyn TransportPeeler,
        adapter: &dyn TransportAdapter,
        msg: TransportMessage,
    ) {
        assert_send(engine.ingest(msg.clone()));
        assert_send(peeler.peel_welcome(&msg));
        assert_send(adapter.receive());
    }

    let _ = assert_trait_futures;
}
