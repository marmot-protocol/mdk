use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::{ScenarioSpec, ScenarioStep};
use marmot_forensics::{ForensicsBundle, ForensicsMessage};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicsAnalysisReport {
    pub bundle_count: u32,
    pub warnings: Vec<String>,
    pub groups: Vec<AnalyzedGroup>,
    pub branch_conflicts: Vec<BranchConflict>,
    pub scenario_spec: ScenarioSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzedGroup {
    pub group_id: String,
    pub observed_epochs: Vec<ObservedEpoch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedEpoch {
    pub account_id: String,
    pub epoch: u64,
    pub message_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchConflict {
    pub group_id: String,
    pub source_epoch: u64,
    pub commit_digests: Vec<ObservedCommitDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCommitDigest {
    pub digest: String,
    pub observed_by: Vec<String>,
}

pub fn analyze_bundles(bundles: &[ForensicsBundle]) -> ForensicsAnalysisReport {
    let warnings = analyze_warnings(bundles);
    let groups = analyze_groups(bundles);
    let branch_conflicts = analyze_branch_conflicts(bundles);
    let scenario_spec = scenario_spec_from_report_inputs(bundles, &branch_conflicts);
    ForensicsAnalysisReport {
        bundle_count: bundles.len() as u32,
        warnings,
        groups,
        branch_conflicts,
        scenario_spec,
    }
}

fn analyze_warnings(bundles: &[ForensicsBundle]) -> Vec<String> {
    let public_salts = bundles
        .iter()
        .filter(|bundle| !bundle.mode.is_sensitive())
        .map(|bundle| bundle.redaction_salt_id.as_deref().unwrap_or("<missing>"))
        .collect::<BTreeSet<_>>();
    if public_salts.len() > 1 {
        vec![
            "public dumps use different redaction salt ids; redacted identifiers and salted digests may not correlate across bundles"
                .to_owned(),
        ]
    } else {
        Vec::new()
    }
}

fn analyze_groups(bundles: &[ForensicsBundle]) -> Vec<AnalyzedGroup> {
    let mut grouped: BTreeMap<String, Vec<ObservedEpoch>> = BTreeMap::new();
    for bundle in bundles {
        grouped
            .entry(bundle.group.group_id.clone())
            .or_default()
            .push(ObservedEpoch {
                account_id: bundle.account.account_id.clone(),
                epoch: bundle.group.epoch,
                message_count: bundle.messages.len() as u32,
            });
    }
    grouped
        .into_iter()
        .map(|(group_id, mut observed_epochs)| {
            observed_epochs.sort_by(|a, b| a.account_id.cmp(&b.account_id));
            AnalyzedGroup {
                group_id,
                observed_epochs,
            }
        })
        .collect()
}

fn analyze_branch_conflicts(bundles: &[ForensicsBundle]) -> Vec<BranchConflict> {
    let mut by_group_epoch_digest: BTreeMap<(String, u64, String), BTreeSet<String>> =
        BTreeMap::new();
    for bundle in bundles {
        for message in &bundle.messages {
            let Some((source_epoch, digest)) = commit_source_and_digest(message) else {
                continue;
            };
            by_group_epoch_digest
                .entry((bundle.group.group_id.clone(), source_epoch, digest))
                .or_default()
                .insert(bundle.account.account_id.clone());
        }
    }

    let mut by_group_epoch: BTreeMap<(String, u64), Vec<ObservedCommitDigest>> = BTreeMap::new();
    for ((group_id, source_epoch, digest), observed_by) in by_group_epoch_digest {
        by_group_epoch
            .entry((group_id, source_epoch))
            .or_default()
            .push(ObservedCommitDigest {
                digest,
                observed_by: observed_by.into_iter().collect(),
            });
    }

    by_group_epoch
        .into_iter()
        .filter_map(|((group_id, source_epoch), mut commit_digests)| {
            if commit_digests.len() < 2 {
                return None;
            }
            commit_digests.sort_by(|a, b| a.digest.cmp(&b.digest));
            Some(BranchConflict {
                group_id,
                source_epoch,
                commit_digests,
            })
        })
        .collect()
}

fn commit_source_and_digest(message: &ForensicsMessage) -> Option<(u64, String)> {
    let openmls = message.openmls.as_ref()?;
    (openmls.content_kind == "commit")
        .then_some((openmls.source_epoch?, openmls.message_digest.clone()))
}

fn scenario_spec_from_report_inputs(
    bundles: &[ForensicsBundle],
    branch_conflicts: &[BranchConflict],
) -> ScenarioSpec {
    let clients = bundles
        .iter()
        .map(|bundle| bundle.account.account_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(idx, _)| format!("device{}", idx + 1))
        .collect::<Vec<_>>();
    let mut steps = Vec::new();
    if !clients.is_empty() {
        steps.push(ScenarioStep::Observe {
            clients: clients.clone(),
        });
    }
    ScenarioSpec {
        name: if branch_conflicts.is_empty() {
            "forensics-observation/v1".to_owned()
        } else {
            "forensics-branch-conflict/v1".to_owned()
        },
        spec_version: "1".to_owned(),
        clients,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use marmot_forensics::{
        FORENSICS_SCHEMA_VERSION, ForensicsAccount, ForensicsBundle, ForensicsDumpMode,
        ForensicsGroup, ForensicsMessage, ForensicsOpenMlsMessage, ForensicsProducer,
    };

    use super::*;

    #[test]
    fn analyzer_reports_same_epoch_commit_conflicts_across_bundles() {
        let alice = bundle("alice", 7, commit("commit-a", 6, "aa"));
        let bob = bundle("bob", 7, commit("commit-b", 6, "bb"));

        let report = analyze_bundles(&[alice, bob]);

        assert_eq!(report.bundle_count, 2);
        assert!(report.warnings.is_empty());
        assert_eq!(report.branch_conflicts.len(), 1);
        let conflict = &report.branch_conflicts[0];
        assert_eq!(conflict.source_epoch, 6);
        assert_eq!(
            conflict
                .commit_digests
                .iter()
                .map(|digest| digest.digest.as_str())
                .collect::<Vec<_>>(),
            vec!["aa", "bb"]
        );
        assert_eq!(report.scenario_spec.name, "forensics-branch-conflict/v1");
        assert_eq!(report.scenario_spec.clients, vec!["device1", "device2"]);
    }

    #[test]
    fn analyzer_warns_when_public_dumps_use_different_redaction_salts() {
        let mut alice = bundle("alice", 7, commit("commit-a", 6, "aa"));
        alice.mode = ForensicsDumpMode::Public;
        alice.redaction_salt_id = Some("salt-a".to_owned());
        let mut bob = bundle("bob", 7, commit("commit-b", 6, "bb"));
        bob.mode = ForensicsDumpMode::Public;
        bob.redaction_salt_id = Some("salt-b".to_owned());

        let report = analyze_bundles(&[alice, bob]);

        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("different redaction salt ids"));
    }

    #[test]
    fn analyzer_warns_when_public_dump_redaction_salt_is_missing() {
        let mut alice = bundle("alice", 7, commit("commit-a", 6, "aa"));
        alice.mode = ForensicsDumpMode::Public;
        alice.redaction_salt_id = Some("salt-a".to_owned());
        let mut bob = bundle("bob", 7, commit("commit-b", 6, "bb"));
        bob.mode = ForensicsDumpMode::Public;

        let report = analyze_bundles(&[alice, bob]);

        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("different redaction salt ids"));
    }

    fn bundle(account_id: &str, epoch: u64, message: ForensicsMessage) -> ForensicsBundle {
        ForensicsBundle {
            schema_version: FORENSICS_SCHEMA_VERSION.to_owned(),
            mode: ForensicsDumpMode::Sensitive,
            redaction_salt_id: None,
            exported_at_ms: 1,
            producer: ForensicsProducer {
                name: "test".to_owned(),
                version: "0".to_owned(),
            },
            account: ForensicsAccount {
                account_ref: account_id.to_owned(),
                account_id: account_id.to_owned(),
            },
            group: ForensicsGroup {
                group_id: "group".to_owned(),
                epoch,
                member_count: 2,
                required_app_components: Vec::new(),
                admins: Vec::new(),
                relays: Vec::new(),
                nostr_group_id: None,
            },
            messages: vec![message],
            snapshots: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn commit(message_id: &str, source_epoch: u64, digest: &str) -> ForensicsMessage {
        ForensicsMessage {
            message_id: message_id.to_owned(),
            group_id: "group".to_owned(),
            epoch: source_epoch,
            state: "created".to_owned(),
            payload_kind: "openmls_wire".to_owned(),
            envelope_kind: "group_message".to_owned(),
            timestamp: 1,
            payload_len: 0,
            payload_digest: "sha256:00".to_owned(),
            payload_hex: Some(String::new()),
            openmls: Some(ForensicsOpenMlsMessage {
                content_kind: "commit".to_owned(),
                source_epoch: Some(source_epoch),
                message_digest: digest.to_owned(),
            }),
        }
    }
}
