//! Typed, replayable real-runtime stimuli and evidence of their execution.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioProfileUpdate {
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioStimulusObservation {
    RelayInterruption {
        action_id: String,
        requested_outage_ms: u64,
        closed_connections: u64,
        rejected_connections: u64,
        runtimes_running: usize,
    },
    ConcurrentProfiles {
        action_id: String,
        /// Callers released together; this does not claim an MLS commit race.
        callers_released: usize,
        outcomes: Vec<crate::app_runtime::ConcurrentMutationOutcome>,
        admitted_publications: usize,
    },
}

/// Reject an assurance report when the requested runtime stimulus was absent,
/// refused, or was merely recorded without cutting any live connection.
pub fn validate_scenario_stimulus_evidence(
    scenario: &crate::ScenarioSpec,
    observations: &[ScenarioStimulusObservation],
) -> Result<(), String> {
    let compiled = crate::compile_scenario(scenario).map_err(|error| error.to_string())?;
    for action in compiled.actions {
        let matching = observations
            .iter()
            .filter(|observation| match observation {
                ScenarioStimulusObservation::RelayInterruption { action_id, .. }
                | ScenarioStimulusObservation::ConcurrentProfiles { action_id, .. } => {
                    action_id == &action.schedule.action_id
                }
            })
            .collect::<Vec<_>>();
        let valid = match &action.step {
            crate::ScenarioStep::InterruptRelay { outage_ms, .. } => matches!(matching.as_slice(),
                [ScenarioStimulusObservation::RelayInterruption { requested_outage_ms, closed_connections, runtimes_running, .. }]
                    if requested_outage_ms == outage_ms && *closed_connections > 0 && *runtimes_running > 0),
            crate::ScenarioStep::RaceGroupProfiles { updates } => matches!(matching.as_slice(),
                [ScenarioStimulusObservation::ConcurrentProfiles { callers_released, outcomes, .. }]
                    if *callers_released == updates.len() && outcomes.len() == updates.len()
                    && outcomes.iter().zip(updates).all(|(outcome, update)| outcome.client == update.client && outcome.accepted && outcome.error_kind.is_none())),
            _ => continue,
        };
        if !valid {
            return Err(format!(
                "missing or invalid stimulus evidence for {}",
                action.schedule.action_id
            ));
        }
    }
    Ok(())
}
