use cgka_engine::convergence::{AppWitness, BranchCandidate, BranchScore, ConvergencePolicy};
use cgka_traits::engine::CommitOrderingPriority;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyCase {
    pub name: String,
    pub scenario: String,
    pub current_tip_epoch: u64,
    pub policy: PolicyCasePolicy,
    pub expected: ExpectedSelection,
    pub branches: Vec<PolicyCaseBranch>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyCasePolicy {
    pub max_rewind_commits: u64,
    pub witness_quorum_senders_per_epoch: usize,
    pub witness_quorum_epochs: usize,
    pub max_witness_override_depth: u64,
}

impl From<&PolicyCasePolicy> for ConvergencePolicy {
    fn from(value: &PolicyCasePolicy) -> Self {
        Self {
            max_rewind_commits: value.max_rewind_commits,
            witness_quorum_senders_per_epoch: value.witness_quorum_senders_per_epoch,
            witness_quorum_epochs: value.witness_quorum_epochs,
            max_witness_override_depth: value.max_witness_override_depth,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExpectedSelection {
    pub branch: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyCaseBranch {
    pub id: String,
    pub fork_epoch: u64,
    pub tip_epoch: u64,
    #[serde(default)]
    pub tip_priority: Option<String>,
    #[serde(default)]
    pub tip_committer: Option<String>,
    pub tip_digest: String,
    pub app_witnesses: Vec<PolicyCaseWitness>,
}

impl PolicyCaseBranch {
    pub fn to_candidate(&self) -> BranchCandidate {
        BranchCandidate {
            id: self.id.clone(),
            fork_epoch: self.fork_epoch,
            tip_epoch: self.tip_epoch,
            tip_priority: priority_from_rank(self.tip_priority.as_deref()),
            tip_committer: self
                .tip_committer
                .as_deref()
                .unwrap_or(&self.id)
                .as_bytes()
                .to_vec(),
            tip_digest: digest_from_rank(&self.tip_digest),
            app_witnesses: self
                .app_witnesses
                .iter()
                .map(PolicyCaseWitness::to_witness)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyCaseWitness {
    pub epoch: u64,
    pub sender: String,
}

impl PolicyCaseWitness {
    fn to_witness(&self) -> AppWitness {
        AppWitness {
            epoch: self.epoch,
            sender: self.sender.as_bytes().to_vec(),
        }
    }
}

pub fn parse_policy_cases(contents: &str) -> Vec<PolicyCase> {
    serde_json::from_str(contents).expect("policy cases JSON parses")
}

pub fn reason_against(expected: &BranchScore, other: &BranchScore) -> &'static str {
    if expected.effective_commit_depth > other.effective_commit_depth {
        return "effective_depth";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met
        && !other.witness_quorum_met
    {
        return "quorum_tie";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met == other.witness_quorum_met
        && expected.valid_commit_depth > other.valid_commit_depth
    {
        return "raw_depth_tie";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met == other.witness_quorum_met
        && expected.valid_commit_depth == other.valid_commit_depth
        && expected.app_witness_score > other.app_witness_score
    {
        return "witness_score_tie";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met == other.witness_quorum_met
        && expected.valid_commit_depth == other.valid_commit_depth
        && expected.app_witness_score == other.app_witness_score
        && expected.tip_priority < other.tip_priority
    {
        return "priority_tie";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met == other.witness_quorum_met
        && expected.valid_commit_depth == other.valid_commit_depth
        && expected.app_witness_score == other.app_witness_score
        && expected.tip_priority == other.tip_priority
        && expected.tip_committer < other.tip_committer
    {
        return "committer_tie";
    }
    if expected.effective_commit_depth == other.effective_commit_depth
        && expected.witness_quorum_met == other.witness_quorum_met
        && expected.valid_commit_depth == other.valid_commit_depth
        && expected.app_witness_score == other.app_witness_score
        && expected.tip_priority == other.tip_priority
        && expected.tip_committer == other.tip_committer
        && expected.tip_digest < other.tip_digest
    {
        return "digest_tie";
    }
    "not_winner"
}

pub fn digest_rank(digest: &[u8; 32]) -> &'static str {
    if digest == &[0x00; 32] {
        "g00"
    } else if digest == &[0xff; 32] {
        "gff"
    } else {
        "gxx"
    }
}

fn digest_from_rank(rank: &str) -> [u8; 32] {
    match rank {
        "00" | "g00" => [0x00; 32],
        "ff" | "gff" => [0xff; 32],
        other => panic!("unsupported digest rank {other:?}"),
    }
}

fn priority_from_rank(rank: Option<&str>) -> CommitOrderingPriority {
    match rank.unwrap_or("ordinary") {
        "privileged" | "admin" => CommitOrderingPriority::Privileged,
        "ordinary" | "member" => CommitOrderingPriority::Ordinary,
        other => panic!("unsupported priority rank {other:?}"),
    }
}
