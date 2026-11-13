//! History recovery's ledger side under one parent (mdk#2782): the recovery
//! runner, the coverage-ledger recorder, epoch-gap detection and the "history
//! may be incomplete" notices. Native replay ingress, the delivery spill and
//! the transport cursor are ingest and stay in `client`.
//!
//! Each child keeps the reach it had as a direct child of `client`.

pub(crate) mod epoch_stall;
pub(crate) mod history_notices;
pub(in crate::client) mod recovery_coverage;
pub(crate) mod recovery_runner;
