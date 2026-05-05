//! # cgka-engine
//!
//! OpenMLS-backed implementation of [`cgka_traits::CgkaEngine`].
//!
//! The engine is generic over any `S: StorageProvider` — no `dyn` storage.
//! The state machine lives above OpenMLS; MLS semantics stay inside OpenMLS
//! (`docs/marmot-architecture/further-context/cgka-engine-design.md:52`).
//!
//! ## Module layout
//!
//! - [`engine`] — the [`Engine<S>`] struct + its [`EngineBuilder`].
//! - [`identity`] — local signer + credential bundle.
//! - [`feature_registry`] — runtime feature registry (replaces static constants).
//! - [`wire_format`] — `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + grep marker.
//! - [`provider`] — ad-hoc `OpenMlsProvider` adapter composed from crypto +
//!   storage.
//!
//! Internal subsystems (Phase 4 — see `AGENTS.md` for the responsibility map):
//!
//! | Subsystem              | Module                  | Task      | Status   |
//! | ---                    | ---                     | ---       | ---      |
//! | `EngineBuilder`        | [`engine`]              | 4.1       | Landed   |
//! | GroupLifecycle         | [`group_lifecycle`]     | 4.2       | Landed (`update_group_data` stubbed) |
//! | MessageProcessor       | [`message_processor`]   | 4.3       | Landed   |
//! | EpochManager           | [`epoch_manager`]       | 4.4 / 4.5 | Landed   |
//! | ForkRecoveryManager    | [`fork_recovery`]       | 4.5+      | Landed (same-epoch deterministic rollback/replay) |
//! | CapabilityManager      | [`capability_manager`]  | 4.6 / 4.7 | Landed   |
//! | KeyPackageManager      | [`key_package`]         | 4.8       | Landed   |
//! | MIP-03 guards          | [`message_processor`] + [`auto_committer`] | 4.9 | Landed |
//! | Wire format policy     | [`wire_format`]         | 4.10      | Landed (revisit before external rollout) |
//! | LowestIndex policy     | [`auto_committer`]      | 4.11      | Landed   |
//! | `drain_*` queues       | [`engine`]              | 4.12      | Landed   |
//! | Publish-before-apply   | [`publish`]             | 4.13      | Landed (auto-commit deliberately still merges immediately — see `auto_committer.rs` rustdoc) |
//! | Group data extension   | [`group_data`]          | MIP-01    | Landed (placeholders for transport-y fields) |
//! | Capability upgrade     | [`upgrade`]             | 4.6       | Landed   |

pub mod auto_committer;
pub mod capabilities;
pub mod capability_manager;
pub mod engine;
pub mod epoch_manager;
pub mod feature_registry;
pub mod fork_recovery;
pub mod group_context_view;
pub mod group_data;
pub mod group_lifecycle;
pub mod identity;
pub mod key_package;
pub mod message_processor;
pub mod provider;
pub mod publish;
pub mod update_group_data;
pub mod upgrade;
pub mod wire_format;

pub use engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
pub use feature_registry::FeatureRegistry;
pub use wire_format::{
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, WIRE_FORMAT_POLICY_REVIEW_REQUIRED, default_join_config,
};

// ── Compile-time witnesses ──────────────────────────────────────────────────

const _: fn(Box<dyn cgka_traits::CgkaEngine + Send + Sync>) = |_| {};
