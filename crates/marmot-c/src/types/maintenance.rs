//! C mirrors of the KeyPackage- and group-maintenance conversions.

use marmot_uniffi::conversions::{
    GroupEvolutionPhaseFfi, GroupEvolutionStatusFfi, GroupMaintenanceStatusFfi,
    KeyPackageMaintenanceStatusFfi, MaintenanceObligationFfi, MaintenancePhaseFfi,
    MaintenanceRunSummaryFfi, MaintenanceTriggerFfi, PeriodicMaintenancePolicyFfi,
    TransportFanoutStatusFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Why a maintenance obligation exists.
    MarmotMaintenanceTrigger from MaintenanceTriggerFfi {
        PostJoin,
        Periodic,
        Manual,
    }
}

c_enum! {
    /// Where an obligation sits in the publish/fan-out lifecycle.
    MarmotMaintenancePhase from MaintenancePhaseFfi {
        CatchUp,
        EoseTimeout,
        Grace,
        Quiet,
        Jitter,
        Overdue,
        Paused,
        ClockSkewBlocked,
        PendingPublication,
        Fanout,
        Retry,
        SupersededByConvergence,
        Complete,
        Failed,
    }
}

c_enum! {
    /// Where a group evolution sits between two epochs.
    MarmotGroupEvolutionPhase from GroupEvolutionPhaseFfi {
        Preparing,
        Prepared,
        Attempting,
        Confirmed,
        SupersededByConvergence,
    }
}

c_mirror! {
    /// One outstanding maintenance obligation.
    MarmotMaintenanceObligation from MaintenanceObligationFfi {
        str id_hex,
        copy trigger: MarmotMaintenanceTrigger,
        copy phase: MarmotMaintenancePhase,
        copy created_at: u64,
        opt_copy has_operational_target_at/operational_target_at: u64,
        copy overdue: bool,
        opt_copy has_eose_deadline_at/eose_deadline_at: u64,
        opt_copy has_grace_until/grace_until: u64,
        opt_copy has_quiet_since/quiet_since: u64,
        copy sampled_jitter_ms: u64,
        opt_copy has_not_before/not_before: u64,
        copy attempt_count: u32,
        copy semantic_rearm_count: u32,
        opt_str last_failure_code,
    }
}

c_mirror! {
    /// One in-flight epoch evolution.
    MarmotGroupEvolutionStatus from GroupEvolutionStatusFfi {
        str id_hex,
        copy phase: MarmotGroupEvolutionPhase,
        copy source_epoch: u64,
        copy target_epoch: u64,
        opt_str signed_message_id_hex,
    }
}

c_mirror! {
    /// Per-obligation transport fan-out counters (no relay identities).
    MarmotTransportFanoutStatus from TransportFanoutStatusFfi {
        str id_hex,
        copy accepted: u32,
        copy unattempted: u32,
        copy attempted_failed: u32,
        copy policy_prohibited: u32,
        copy required_acks: u32,
        copy evolution_confirmed: bool,
        opt_copy has_bounded_until/bounded_until: u64,
    }
}

c_mirror! {
    /// One group's maintenance state. Free with
    /// `marmot_group_maintenance_status_free`.
    MarmotGroupMaintenanceStatus from GroupMaintenanceStatusFfi,
    free marmot_group_maintenance_status_free {
        str group_id_hex,
        opt_copy has_enrolled_at/enrolled_at: u64,
        copy periodic_enrolled: bool,
        opt_copy has_last_own_leaf_rotation_at/last_own_leaf_rotation_at: u64,
        opt_copy has_next_periodic_rotation_at/next_periodic_rotation_at: u64,
        vec obligations/obligations_len: MarmotMaintenanceObligation,
        vec evolutions/evolutions_len: MarmotGroupEvolutionStatus,
        vec fanouts/fanouts_len: MarmotTransportFanoutStatus,
        copy paused: bool,
    }
}

c_mirror! {
    /// The account's KeyPackage slot state. Free with
    /// `marmot_key_package_maintenance_status_free`.
    MarmotKeyPackageMaintenanceStatus from KeyPackageMaintenanceStatusFfi,
    free marmot_key_package_maintenance_status_free {
        str stable_slot_id,
        copy phase: MarmotMaintenancePhase,
        opt_str current_key_package_ref_hex,
        opt_copy has_current_not_before/current_not_before: u64,
        opt_copy has_current_not_after/current_not_after: u64,
        opt_str authored_event_id_hex,
        opt_copy has_authored_event_created_at/authored_event_created_at: u64,
        copy accepted_fanout_targets: u32,
        copy unattempted_fanout_targets: u32,
        copy failed_fanout_targets: u32,
        copy policy_prohibited_fanout_targets: u32,
        opt_copy has_refresh_at/refresh_at: u64,
        opt_str last_consumed_key_package_ref_hex,
        copy retained_private_material_count: u32,
        opt_str pending_event_id_hex,
        copy pending_attempt_count: u32,
        opt_str pending_last_failure_code,
    }
}

c_enum! {
    /// Whether new groups enroll in periodic maintenance.
    MarmotPeriodicMaintenancePolicy from PeriodicMaintenancePolicyFfi {
        EnabledForNewGroups,
        Disabled,
    }
}

impl From<MarmotPeriodicMaintenancePolicy> for PeriodicMaintenancePolicyFfi {
    fn from(value: MarmotPeriodicMaintenancePolicy) -> Self {
        match value {
            MarmotPeriodicMaintenancePolicy::EnabledForNewGroups => Self::EnabledForNewGroups,
            MarmotPeriodicMaintenancePolicy::Disabled => Self::Disabled,
        }
    }
}

c_mirror! {
    /// What one maintenance pass did. Free with
    /// `marmot_maintenance_run_summary_free`.
    MarmotMaintenanceRunSummary from MaintenanceRunSummaryFfi,
    free marmot_maintenance_run_summary_free {
        copy published: u32,
        str_vec message_ids/message_ids_len,
        copy deferred: u32,
        copy ambiguous_exposure: u32,
        copy failures: u32,
    }
}
