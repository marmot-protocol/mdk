//! Engine-owned pairing-session lifecycle tests.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::maintenance::{MaintenanceRandom, WallClock};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, Timestamp, TransportMessage};
use cgka_traits::{CgkaEngine, DEFAULT_PAIRING_SESSION_TTL_MS, MemberId, PairingSessionState};
use marmot_forensics::{AuditEventKind, AuditRecord, ForensicRecorder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

#[derive(Default)]
struct ManualWallClock(AtomicU64);

impl ManualWallClock {
    fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    fn advance(&self, delta_ms: u64) {
        self.0.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl WallClock for ManualWallClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.now_ms() / 1_000)
    }

    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct FixedMaintenanceRandom;

impl MaintenanceRandom for FixedMaintenanceRandom {
    fn next_u64(&self) -> u64 {
        0
    }
}

struct StubPeeler;

#[async_trait]
impl TransportPeeler for StubPeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_group_message(
        &self,
        _payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }
}

fn valid_identity(seed: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};

    let mut counter = 0u64;
    loop {
        let material: [u8; 32] = Sha256::new()
            .chain_update(b"cgka-engine-test-identity-v1")
            .chain_update(seed)
            .chain_update(counter.to_be_bytes())
            .finalize()
            .into();
        if let Ok(key) = SigningKey::from_bytes(&material) {
            return key.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

fn build_engine(clock: Arc<ManualWallClock>) -> cgka_engine::Engine<SqliteAccountStorage> {
    build_engine_with_recorder(clock, None)
}

fn build_engine_with_recorder(
    clock: Arc<ManualWallClock>,
    recorder: Option<Box<dyn ForensicRecorder>>,
) -> cgka_engine::Engine<SqliteAccountStorage> {
    let mut builder = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(valid_identity(b"pairing-session"))
        .account_identity_proof_signer(proof_signer(b"pairing-session"))
        .peeler(Box::new(StubPeeler))
        .maintenance_sources(clock, Arc::new(FixedMaintenanceRandom));
    if let Some(recorder) = recorder {
        builder = builder.recorder(recorder);
    }
    builder.build().expect("build engine")
}

#[derive(Clone, Default)]
struct CapturingRecorder(Arc<Mutex<Vec<AuditEventKind>>>);

impl ForensicRecorder for CapturingRecorder {
    fn record(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record.kind);
    }
}

impl CapturingRecorder {
    fn kinds(&self) -> Vec<AuditEventKind> {
        self.0.lock().unwrap().clone()
    }
}

#[test]
fn rotation_expires_old_qr_and_returns_fresh_material() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let mut engine = build_engine(clock.clone());

    let first = engine.start_pairing_session().expect("start first session");
    assert_eq!(
        engine.pairing_session_state(&first.session_id),
        Ok(PairingSessionState::Active)
    );
    assert_eq!(first.expires_at_ms, 1_000 + DEFAULT_PAIRING_SESSION_TTL_MS);

    clock.advance(DEFAULT_PAIRING_SESSION_TTL_MS);
    let second = engine
        .start_pairing_session()
        .expect("rotate expired session");

    assert_ne!(second.session_id, first.session_id);
    assert_ne!(second.ephemeral_public_key, first.ephemeral_public_key);
    assert_eq!(
        engine.pairing_session_state(&first.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );
    assert_eq!(
        engine.pairing_session_state(&second.session_id),
        Ok(PairingSessionState::Active)
    );
}

#[test]
fn expired_session_is_rejected_before_scan() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let mut engine = build_engine(clock.clone());
    let session = engine.start_pairing_session().expect("start session");

    clock.advance(DEFAULT_PAIRING_SESSION_TTL_MS);

    assert_eq!(
        engine.scan_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );
}

#[test]
fn stale_qr_loses_to_newest_session() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let mut engine = build_engine(clock);

    let stale = engine.start_pairing_session().expect("start stale session");
    let current = engine
        .start_pairing_session()
        .expect("start winner session");

    assert_eq!(
        engine.scan_pairing_session(&stale.session_id),
        Err(cgka_traits::PairingSessionError::Superseded)
    );
    assert_eq!(engine.scan_pairing_session(&current.session_id), Ok(()));
    assert_eq!(
        engine.pairing_session_state(&current.session_id),
        Ok(PairingSessionState::Scanned)
    );
}

#[test]
fn approved_session_is_single_use_and_requires_a_scan() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let mut engine = build_engine(clock);
    let session = engine.start_pairing_session().expect("start session");

    assert_eq!(
        engine.approve_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::NotScanned)
    );
    engine
        .scan_pairing_session(&session.session_id)
        .expect("scan session");
    engine
        .approve_pairing_session(&session.session_id)
        .expect("approve session");

    assert_eq!(
        engine.pairing_session_state(&session.session_id),
        Ok(PairingSessionState::Approved)
    );
    assert_eq!(
        engine.approve_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::AlreadyAccepted)
    );
    assert_eq!(
        engine.scan_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::AlreadyAccepted)
    );
}

#[test]
fn rejected_session_remains_terminal_until_its_ttl() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let mut engine = build_engine(clock.clone());
    let session = engine.start_pairing_session().expect("start session");
    engine
        .scan_pairing_session(&session.session_id)
        .expect("scan session");
    engine
        .reject_pairing_session(&session.session_id)
        .expect("reject session");

    assert_eq!(
        engine.pairing_session_state(&session.session_id),
        Ok(PairingSessionState::Rejected)
    );
    assert_eq!(
        engine.approve_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::Rejected)
    );

    clock.advance(DEFAULT_PAIRING_SESSION_TTL_MS);
    assert_eq!(
        engine.pairing_session_state(&session.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );
}

#[test]
fn restart_fails_closed_for_in_flight_session() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let session = {
        let mut engine = build_engine(clock.clone());
        engine.start_pairing_session().expect("start session")
    };

    let mut restarted = build_engine(clock);
    assert_eq!(
        restarted.pairing_session_state(&session.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );
    assert_eq!(
        restarted.scan_pairing_session(&session.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );
}

#[test]
fn every_pairing_transition_emits_a_privacy_safe_audit_row() {
    let clock = Arc::new(ManualWallClock::new(1_000));
    let capture = CapturingRecorder::default();
    let mut engine = build_engine_with_recorder(clock.clone(), Some(Box::new(capture.clone())));

    let stale = engine.start_pairing_session().unwrap();
    let rejected = engine.start_pairing_session().unwrap();
    assert_eq!(
        engine.pairing_session_state(&stale.session_id),
        Ok(PairingSessionState::Superseded)
    );
    engine.scan_pairing_session(&rejected.session_id).unwrap();
    engine.reject_pairing_session(&rejected.session_id).unwrap();

    let expired = engine.start_pairing_session().unwrap();
    clock.advance(DEFAULT_PAIRING_SESSION_TTL_MS);
    assert_eq!(
        engine.pairing_session_state(&expired.session_id),
        Err(cgka_traits::PairingSessionError::Expired)
    );

    let approved = engine.start_pairing_session().unwrap();
    engine.scan_pairing_session(&approved.session_id).unwrap();
    engine
        .approve_pairing_session(&approved.session_id)
        .unwrap();

    let kinds = capture.kinds();
    let transitions: Vec<(Option<&str>, &str, &str)> = kinds
        .iter()
        .filter_map(|kind| match kind {
            AuditEventKind::PairingSession {
                previous_state,
                new_state,
                reason,
                ..
            } => Some((
                previous_state.as_deref(),
                new_state.as_str(),
                reason.as_str(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        transitions,
        vec![
            (None, "active", "started"),
            (Some("active"), "superseded", "new_session_started"),
            (None, "active", "started"),
            (Some("active"), "scanned", "qr_scanned"),
            (Some("scanned"), "rejected", "local_user_rejected"),
            (None, "active", "started"),
            (Some("active"), "expired", "ttl_elapsed"),
            (None, "active", "started"),
            (Some("active"), "scanned", "qr_scanned"),
            (Some("scanned"), "approved", "local_user_approved"),
        ]
    );
}
