//! Canonical pairing-session races through the public conformance harness.

use cgka_conformance_simulator::{ClientBuilder, TransportBus};
use cgka_traits::{CgkaEngine, PairingSessionError, PairingSessionState};

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let len = name.len().min(out.len());
    out[..len].copy_from_slice(&name[..len]);
    out
}

#[test]
fn stale_qr_race_rejects_first_scan_and_accepts_newest() {
    let bus = TransportBus::ordered();
    let mut account = ClientBuilder::new(pad32(b"alice")).attach(&bus);

    let stale = account
        .engine_mut()
        .start_pairing_session()
        .expect("start first pairing QR");
    let current = account
        .engine_mut()
        .start_pairing_session()
        .expect("rotate pairing QR");

    assert_eq!(
        account.engine_mut().scan_pairing_session(&stale.session_id),
        Err(PairingSessionError::Superseded)
    );
    account
        .engine_mut()
        .scan_pairing_session(&current.session_id)
        .expect("newest QR wins");
    assert_eq!(
        account
            .engine_mut()
            .pairing_session_state(&current.session_id),
        Ok(PairingSessionState::Scanned)
    );
}
