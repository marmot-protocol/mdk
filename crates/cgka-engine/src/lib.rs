//! # cgka-engine
//!
//! OpenMLS-backed implementation of [`cgka_traits::CgkaEngine`].
//!
//! The engine is generic over any `S: StorageProvider`; storage dispatch is
//! static. OpenMLS owns MLS validation and key schedule state. Marmot owns the
//! application-facing state machine, durable message records, convergence
//! policy, feature negotiation, and transport wrapping boundary.
//!
//! The state machine lives above OpenMLS; MLS semantics stay inside OpenMLS
//! (`docs/marmot-architecture/further-context/cgka-engine-design.md:52`).
//!
//! ## Module layout
//!
//! - [`engine`] — the [`Engine<S>`] struct + its [`EngineBuilder`].
//! - [`engine_metrics`] — diagnostic post-settle reorg telemetry.
//! - [`identity`] — local signer + credential bundle.
//! - [`account_identity_proof`] — account-key proof binding credentials to MLS leaves.
//! - [`feature_registry`] — runtime feature registry (replaces static constants).
//! - [`wire_format`] - `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` and review marker.
//! - [`provider`] - `OpenMlsProvider` adapter composed from crypto + storage.
//! - [`group_lifecycle`] - `create_group`, `join_welcome`, group records.
//! - [`message_processor`] - inbound `ingest` and outbound `send`.
//! - [`distributed_convergence`] - stored-message convergence entry points.
//! - [`canonicalization`] and [`convergence`] - executable policy model.
//! - [`openmls_projection`] - bytes-first bridge between OpenMLS and the model.
//! - [`epoch_manager`] - per-group state transitions and pending references.
//! - [`fork_recovery`] - same-epoch commit rollback/replay support.
//! - [`publish`] - publish-confirm and publish-failed lifecycle.
//! - [`capability_manager`], [`capabilities`], [`upgrade`] - capability policy.
//! - [`auto_committer`] - deterministic SelfRemove auto-commit policy.
//! - [`app_components`] - Marmot app-component state in `app_data_dictionary`.

pub mod account_identity_proof;
pub mod app_components;

pub(crate) mod app_payload;
pub(crate) mod audit_helpers;
pub mod auto_committer;
pub mod canonicalization;
pub mod capabilities;
pub mod capability_manager;
pub mod convergence;
pub mod distributed_convergence;
pub mod engine;
pub mod engine_metrics;
pub mod epoch_manager;
pub mod feature_registry;
pub mod fork_recovery;
pub mod group_context_view;
pub mod group_lifecycle;
pub mod group_state_changes;
pub mod identity;
pub mod key_package;
pub mod message_processor;
pub mod openmls_projection;
pub mod pending_commit_guard;
pub mod provider;
pub mod publish;
pub mod snapshot_guard;
pub mod update_group_data;
pub mod upgrade;
pub mod wire_format;

pub use engine::{Ciphersuite, DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
pub use engine_metrics::{
    EngineMetrics, EngineMetricsSnapshot, HistogramBucket, HistogramSnapshot,
};
pub use feature_registry::FeatureRegistry;
pub use key_package::{KeyPackageMetadata, key_package_metadata};
pub use wire_format::{
    DEFAULT_MAX_PAST_EPOCHS, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, WIRE_FORMAT_POLICY_REVIEW_REQUIRED,
    default_join_config, join_config,
};

// ── Compile-time witnesses ──────────────────────────────────────────────────

const _: fn(Box<dyn cgka_traits::CgkaEngine + Send + Sync>) = |_| {};
