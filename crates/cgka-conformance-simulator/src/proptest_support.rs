//! proptest strategies for generating SendIntent sequences and delivery
//! schedules. Used by the property tests in `tests/proptest_invariants.rs`.
//!
//! ## What's generated
//!
//! [`HarnessIntent`] enumerates the cgka-conformance-simulator-friendly subset of
//! `SendIntent`:
//! - `Send { sender_idx, payload }` — application message.
//! - `Leave { sender_idx }` — MIP-03 SelfRemove from a non-admin client
//!   (admin self-removal triggers MIP-03 §149/§150 guards we cover in
//!   integration tests, not invariants).
//!
//! `Invite` is intentionally NOT in this enum — minting fresh clients
//! mid-strategy requires `&mut` to a parent state we can't thread through
//! a proptest closure cleanly. Invite happens during scenario setup
//! (`setup_group`), not the strategy itself.
//!
//! ## Delivery configuration
//!
//! [`DeliveryProfile`] selects a `TransportBus` policy. The proptest
//! drives convergence under each profile so the invariant has to hold
//! independent of message ordering.
//!
//! ## Confirmation outcome
//!
//! [`ConfirmOutcome`] picks per-pending whether the harness calls
//! `confirm_published` (success) or `publish_failed` (rollback). The
//! invariant tests use this to assert convergence holds whether
//! intermittent publishes succeed or fail.

use crate::bus::DeliveryPolicy;
use proptest::prelude::*;

/// Test-harness-friendly subset of `SendIntent`. See module doc for why
/// `Invite` is excluded.
#[derive(Clone, Debug)]
pub enum HarnessIntent {
    /// Encrypted application payload from `sender_idx`.
    Send { sender_idx: usize, payload: Vec<u8> },
    /// `sender_idx` issues a SelfRemove proposal. The lowest-index
    /// remaining non-target member auto-commits per MIP-03 §144.
    Leave { sender_idx: usize },
}

/// Delivery profile selector. Maps cleanly onto `TransportBus` policies.
#[derive(Clone, Debug)]
pub enum DeliveryProfile {
    /// FIFO, broadcast welcomes (the canonical scenario shape).
    Ordered,
    /// LIFO — exercises late-arriving-proposal handling.
    Reverse,
    /// Deterministic shuffle from a seed.
    SeededRandom { seed: u64 },
}

impl DeliveryProfile {
    pub fn into_policy(self) -> DeliveryPolicy {
        match self {
            DeliveryProfile::Ordered => DeliveryPolicy::Ordered {
                broadcast_welcomes: true,
            },
            DeliveryProfile::Reverse => DeliveryPolicy::Reverse,
            DeliveryProfile::SeededRandom { seed } => DeliveryPolicy::SeededRandom { seed },
        }
    }
}

/// Per-pending-publish outcome the test will drive.
#[derive(Clone, Copy, Debug)]
pub enum ConfirmOutcome {
    Confirm,
    Fail,
}

// ── Strategies ──────────────────────────────────────────────────────────────

pub fn intent_seq(
    n_clients: usize,
    len: std::ops::Range<usize>,
) -> impl Strategy<Value = Vec<HarnessIntent>> {
    let max_payload = 16usize;
    // Mix of Send + Leave. Leave is rarer (1/4 weight) because it
    // permanently removes the leaver — too many leaves in a short
    // sequence trivialize the convergence test.
    let intent = prop_oneof![
        3 => (
            0..n_clients,
            prop::collection::vec(any::<u8>(), 1..=max_payload),
        )
            .prop_map(|(sender_idx, payload)| HarnessIntent::Send {
                sender_idx,
                payload,
            }),
        1 => (1..n_clients).prop_map(|sender_idx| HarnessIntent::Leave { sender_idx }),
    ];
    prop::collection::vec(intent, len)
}

pub fn delivery_profile() -> impl Strategy<Value = DeliveryProfile> {
    prop_oneof![
        Just(DeliveryProfile::Ordered),
        Just(DeliveryProfile::Reverse),
        any::<u64>().prop_map(|seed| DeliveryProfile::SeededRandom { seed }),
    ]
}

pub fn confirm_outcome() -> impl Strategy<Value = ConfirmOutcome> {
    // Skew toward confirm: fail is the perturbation, not the default.
    prop_oneof![
        4 => Just(ConfirmOutcome::Confirm),
        1 => Just(ConfirmOutcome::Fail),
    ]
}
