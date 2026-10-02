use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use agent_control::AgentControlMediaRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, watch};

use crate::error::Result;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) session_id: String,
    /// Selected working directory, or `None` when this chat has not chosen one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cwd: Option<PathBuf>,
    /// Standing instruction prepended to every prompt in this chat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) goal: Option<String>,
    /// Monotonic session epoch used to reject observations from work that
    /// started before a `/new` or `/cd` boundary.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) generation: u64,
    /// The non-evicting durable journal for applied `/new` commands.
    /// The control protocol supplies no replay horizon or durable low-water
    /// mark. Accept linear growth until it does: eviction would let an old
    /// command reset a newer session after restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reset_receipts: Vec<ResetReceipt>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResetSessionOutcome {
    pub(crate) changed: bool,
    pub(crate) replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResetReceipt {
    message_ref_digest: String,
    changed: bool,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryKind {
    FailedResumable,
    UncertainOutcome,
    PolicyLimit,
    NotResponding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecoveryStatus {
    Pending,
    Retrying,
}

/// Private durable replay obligation. Its contents are never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveryRecord {
    pub(crate) prompt: String,
    #[serde(default)]
    pub(crate) media: Vec<AgentControlMediaRef>,
    pub(crate) cwd: PathBuf,
    pub(crate) session_id: String,
    pub(crate) kind: RecoveryKind,
    pub(crate) status: RecoveryStatus,
}

/// Durable acknowledgement reconciliation for text-only `SendFinal` chunks.
/// Media and mixed-media terminals are intentionally outside this store.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FinalDeliveryRecord {
    pub(crate) account_ref: String,
    pub(crate) group_ref: String,
    pub(crate) reply_to_ref: String,
    pub(crate) text: String,
    pub(crate) chunk_index: usize,
}

/// Lifecycle of one backend turn's durable-send budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TurnPhase {
    /// The live handler owns the turn; replay is excluded.
    Active,
    /// Collection completed safely; pending work may be replayed within budget.
    Reconcilable,
    /// An output limit was exceeded, or the connector stopped while the turn
    /// was active; nothing is sent until explicit discard.
    Limited,
    /// Explicitly discarded while its artifact intents may still be pending.
    /// Nothing is sent and the group stays blocked; the tombstone is removed
    /// only after every matching outbox intent is durably gone.
    Discarded,
}

/// Durable per-turn send accounting. Identities are never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TurnBudgetRecord {
    pub(crate) group_ref: String,
    pub(crate) reply_to_ref: String,
    pub(crate) max_durable_sends: usize,
    pub(crate) sends_charged: usize,
    pub(crate) phase: TurnPhase,
}

impl std::fmt::Debug for TurnBudgetRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnBudgetRecord")
            .field("max_durable_sends", &self.max_durable_sends)
            .field("sends_charged", &self.sends_charged)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// Who is asking to send on behalf of a turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendMode {
    /// The handler that is running or just finished the turn.
    Live,
    /// Startup/periodic reconciliation or artifact replay.
    Replay,
}

/// Result of reserving one durable send before its effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendAdmission {
    Admitted,
    Exhausted,
    Withheld,
}

/// Length-prefixed so no `(group_ref, reply_to_ref)` pair can alias another,
/// whatever alphabet the refs use.
fn turn_key(group_ref: &str, reply_to_ref: &str) -> String {
    format!("{}:{group_ref}:{reply_to_ref}", group_ref.len())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRecord {
    Bare(String),
    Full {
        session_id: String,
        #[serde(default)]
        cwd: Option<PathBuf>,
        #[serde(default)]
        goal: Option<String>,
        #[serde(default)]
        generation: u64,
        #[serde(default)]
        reset_receipts: Vec<ResetReceipt>,
    },
}

impl RawRecord {
    fn into_record(self, default_cwd: &Path) -> SessionRecord {
        match self {
            Self::Bare(session_id) => SessionRecord {
                session_id,
                cwd: Some(default_cwd.to_path_buf()),
                goal: None,
                generation: 0,
                reset_receipts: Vec::new(),
            },
            Self::Full {
                session_id,
                cwd,
                goal,
                generation,
                reset_receipts,
            } => SessionRecord {
                session_id,
                cwd,
                goal,
                generation,
                reset_receipts,
            },
        }
    }
}

pub(crate) struct SessionStore {
    path: PathBuf,
    map: Mutex<HashMap<String, SessionRecord>>,
}

impl SessionStore {
    pub(crate) fn load(path: PathBuf, default_cwd: &Path) -> Result<Self> {
        if path.exists() {
            fs_private::tighten_existing_private_file(&path)?;
        }
        let map = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => {
                let raw: HashMap<String, RawRecord> = serde_json::from_slice(&bytes)?;
                raw.into_iter()
                    .map(|(key, value)| (key, value.into_record(default_cwd)))
                    .collect()
            }
            Ok(_) => HashMap::new(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => return Err(err.into()),
        };
        Ok(Self {
            path,
            map: Mutex::new(map),
        })
    }

    pub(crate) async fn get(&self, group_key: &str) -> Option<SessionRecord> {
        self.map.lock().await.get(group_key).cloned()
    }

    /// Records the backend session and working directory, retaining the goal.
    #[cfg(test)]
    pub(crate) async fn record_session(
        &self,
        group_key: &str,
        session_id: String,
        cwd: PathBuf,
    ) -> Result<()> {
        self.update(group_key, |record| {
            record.session_id = session_id;
            record.cwd = Some(cwd);
        })
        .await
    }

    /// Records a backend observation only if the session epoch that started
    /// the backend run is still current.
    pub(crate) async fn record_session_if_generation(
        &self,
        group_key: &str,
        expected_generation: u64,
        session_id: String,
        cwd: PathBuf,
    ) -> Result<bool> {
        let mut map = self.map.lock().await;
        let current_generation = map.get(group_key).map_or(0, |record| record.generation);
        if current_generation != expected_generation {
            return Ok(false);
        }
        let mut next = map.clone();
        let record = next.entry(group_key.to_owned()).or_default();
        record.session_id = session_id;
        record.cwd = Some(cwd);
        persist(&self.path, &mut map, next).await?;
        Ok(true)
    }

    /// Selects the working directory and starts a new session epoch, retaining
    /// the goal.
    pub(crate) async fn set_workdir(&self, group_key: &str, cwd: PathBuf) -> Result<()> {
        self.update(group_key, |record| {
            record.session_id.clear();
            record.cwd = Some(cwd);
            record.generation = record.generation.saturating_add(1);
        })
        .await
    }

    /// Replaces the standing goal, retaining the session and working directory.
    pub(crate) async fn set_goal(&self, group_key: &str, goal: Option<String>) -> Result<()> {
        self.update(group_key, |record| record.goal = goal).await
    }

    pub(crate) async fn reset_session(
        &self,
        group_key: &str,
        message_ref: &str,
    ) -> Result<ResetSessionOutcome> {
        let mut map = self.map.lock().await;
        let message_ref_digest = (!message_ref.is_empty()).then(|| {
            let mut hasher = Sha256::new();
            hasher.update(message_ref.as_bytes());
            hex::encode(hasher.finalize())
        });
        if let (Some(record), Some(digest)) = (map.get(group_key), message_ref_digest.as_deref())
            && let Some(receipt) = record
                .reset_receipts
                .iter()
                .find(|receipt| receipt.message_ref_digest == digest)
        {
            return Ok(ResetSessionOutcome {
                changed: receipt.changed,
                replayed: true,
            });
        }

        let mut next = map.clone();
        let record = next.entry(group_key.to_owned()).or_default();
        let changed = !record.session_id.is_empty();
        record.session_id.clear();
        record.generation = record.generation.saturating_add(1);
        if let Some(message_ref_digest) = message_ref_digest {
            record.reset_receipts.push(ResetReceipt {
                message_ref_digest,
                changed,
                generation: record.generation,
            });
        }
        persist(&self.path, &mut map, next).await?;
        Ok(ResetSessionOutcome {
            changed,
            replayed: false,
        })
    }

    async fn update(&self, group_key: &str, apply: impl FnOnce(&mut SessionRecord)) -> Result<()> {
        let mut map = self.map.lock().await;
        let mut next = map.clone();
        apply(next.entry(group_key.to_owned()).or_default());
        persist(&self.path, &mut map, next).await
    }
}

async fn persist(
    path: &Path,
    map: &mut HashMap<String, SessionRecord>,
    next: HashMap<String, SessionRecord>,
) -> Result<()> {
    let path = path.to_path_buf();
    let snapshot = next.clone();
    tokio::task::spawn_blocking(move || write_snapshot(&path, &snapshot)).await??;
    *map = next;
    Ok(())
}

pub(crate) struct RecoveryStore {
    path: PathBuf,
    map: Mutex<HashMap<String, RecoveryRecord>>,
}

impl RecoveryStore {
    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        if path.exists() {
            fs_private::tighten_existing_private_file(&path)?;
        }
        let mut map: HashMap<String, RecoveryRecord> = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes)?,
            Ok(_) => HashMap::new(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => return Err(err.into()),
        };
        for record in map.values_mut() {
            if record.status == RecoveryStatus::Retrying {
                record.status = RecoveryStatus::Pending;
            }
        }
        Ok(Self {
            path,
            map: Mutex::new(map),
        })
    }

    pub(crate) async fn get(&self, group_key: &str) -> Option<RecoveryRecord> {
        self.map.lock().await.get(group_key).cloned()
    }

    pub(crate) async fn set(&self, group_key: &str, record: RecoveryRecord) -> Result<()> {
        let mut map = self.map.lock().await;
        let mut next = map.clone();
        next.insert(group_key.to_owned(), record);
        self.commit(&mut map, next).await
    }

    /// Atomically consumes retry authority while retaining the restart barrier.
    pub(crate) async fn begin_retry(&self, group_key: &str) -> Result<Option<RecoveryRecord>> {
        let mut map = self.map.lock().await;
        let Some(current) = map.get(group_key) else {
            return Ok(None);
        };
        if current.status != RecoveryStatus::Pending {
            return Ok(None);
        }
        let mut next = map.clone();
        let record = next.get_mut(group_key).expect("recovery record exists");
        record.status = RecoveryStatus::Retrying;
        let result = record.clone();
        self.commit(&mut map, next).await?;
        Ok(Some(result))
    }

    pub(crate) async fn reset_retry(&self, group_key: &str) -> Result<bool> {
        let mut map = self.map.lock().await;
        let Some(current) = map.get(group_key) else {
            return Ok(false);
        };
        if current.status != RecoveryStatus::Retrying {
            return Ok(false);
        }
        let mut next = map.clone();
        next.get_mut(group_key)
            .expect("recovery record exists")
            .status = RecoveryStatus::Pending;
        self.commit(&mut map, next).await?;
        Ok(true)
    }

    pub(crate) async fn discard(&self, group_key: &str) -> Result<bool> {
        let mut map = self.map.lock().await;
        if !map.contains_key(group_key) {
            return Ok(false);
        }
        let mut next = map.clone();
        next.remove(group_key);
        self.commit(&mut map, next).await?;
        Ok(true)
    }

    async fn commit(
        &self,
        map: &mut tokio::sync::MutexGuard<'_, HashMap<String, RecoveryRecord>>,
        next: HashMap<String, RecoveryRecord>,
    ) -> Result<()> {
        let path = self.path.clone();
        let snapshot = next.clone();
        tokio::task::spawn_blocking(move || write_recovery_snapshot(&path, &snapshot)).await??;
        **map = next;
        Ok(())
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct FinalDeliverySnapshot {
    #[serde(default)]
    records: HashMap<String, FinalDeliveryRecord>,
    #[serde(default)]
    incomplete_finals: HashMap<String, HashSet<String>>,
    #[serde(default)]
    turn_budgets: HashMap<String, TurnBudgetRecord>,
}

impl FinalDeliverySnapshot {
    fn turn_has_records(&self, group_ref: &str, reply_to_ref: &str) -> bool {
        self.records
            .values()
            .any(|record| record.group_ref == group_ref && record.reply_to_ref == reply_to_ref)
    }

    fn turn_phase(&self, group_ref: &str, reply_to_ref: &str) -> Option<TurnPhase> {
        self.turn_budgets
            .get(&turn_key(group_ref, reply_to_ref))
            .map(|budget| budget.phase)
    }

    fn is_incomplete(&self, group_ref: &str, reply_to_ref: &str) -> bool {
        self.incomplete_finals
            .get(group_ref)
            .is_some_and(|reply_tos| reply_tos.contains(reply_to_ref))
    }

    /// No handler survives a restart, so a persisted active turn was
    /// interrupted with an unknown outcome: it may already have breached a
    /// limit. It is loaded as limited behind the incomplete-final barrier, the
    /// same discardable state a live breach leaves, and never replayed. Budgets
    /// are re-keyed from their own identity.
    fn recover_interrupted_turns(&mut self) {
        for (_, mut budget) in std::mem::take(&mut self.turn_budgets) {
            if budget.phase == TurnPhase::Active {
                budget.phase = TurnPhase::Limited;
                self.incomplete_finals
                    .entry(budget.group_ref.clone())
                    .or_default()
                    .insert(budget.reply_to_ref.clone());
            }
            self.turn_budgets
                .insert(turn_key(&budget.group_ref, &budget.reply_to_ref), budget);
        }
    }
}

pub(crate) struct FinalDeliveryStore {
    path: PathBuf,
    state: Mutex<FinalDeliverySnapshot>,
    changed: watch::Sender<u64>,
    fail_next_set: AtomicBool,
    fail_next_budget_write: AtomicBool,
}

impl FinalDeliveryStore {
    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        if path.exists() {
            fs_private::tighten_existing_private_file(&path)?;
        }
        let mut state = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => parse_final_delivery_snapshot(&bytes)?,
            Ok(_) => FinalDeliverySnapshot::default(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                FinalDeliverySnapshot::default()
            }
            Err(err) => return Err(err.into()),
        };
        state.recover_interrupted_turns();
        let (changed, _) = watch::channel(0);
        Ok(Self {
            path,
            state: Mutex::new(state),
            changed,
            fail_next_set: AtomicBool::new(false),
            fail_next_budget_write: AtomicBool::new(false),
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub(crate) async fn has_group(&self, group_ref: &str) -> bool {
        self.state
            .lock()
            .await
            .records
            .values()
            .any(|record| record.group_ref == group_ref)
    }

    pub(crate) async fn has_incomplete_final(&self, group_ref: &str) -> bool {
        self.state
            .lock()
            .await
            .incomplete_finals
            .get(group_ref)
            .is_some_and(|reply_tos| !reply_tos.is_empty())
    }

    /// Whether the group waits only on `/discard-last` (or `/retry-last`): it
    /// holds an incomplete-final barrier or limited turn and no live turn, as
    /// opposed to a running turn or pending reconciliation that resolves itself.
    pub(crate) async fn requires_recovery_command(&self, group_ref: &str) -> bool {
        let state = self.state.lock().await;
        let mut unresolved = state
            .incomplete_finals
            .get(group_ref)
            .is_some_and(|reply_tos| !reply_tos.is_empty());
        for budget in state.turn_budgets.values() {
            if budget.group_ref != group_ref {
                continue;
            }
            match budget.phase {
                TurnPhase::Active => return false,
                TurnPhase::Limited | TurnPhase::Discarded => unresolved = true,
                TurnPhase::Reconcilable => {}
            }
        }
        unresolved
    }

    /// Live, limited and discarded turns block the group like an incomplete
    /// final; a limited turn stays until it is explicitly discarded, and a
    /// discarded one until its artifact intents are removed.
    pub(crate) async fn blocks_group(&self, group_ref: &str) -> bool {
        let unresolved_turn =
            self.state.lock().await.turn_budgets.values().any(|budget| {
                budget.group_ref == group_ref && budget.phase != TurnPhase::Reconcilable
            });
        unresolved_turn
            || self.has_incomplete_final(group_ref).await
            || self.has_group(group_ref).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn list(&self) -> Vec<(String, FinalDeliveryRecord)> {
        let mut records: Vec<_> = self
            .state
            .lock()
            .await
            .records
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        records.sort_by(|(_, left), (_, right)| {
            (
                &left.account_ref,
                &left.group_ref,
                &left.reply_to_ref,
                left.chunk_index,
            )
                .cmp(&(
                    &right.account_ref,
                    &right.group_ref,
                    &right.reply_to_ref,
                    right.chunk_index,
                ))
        });
        records
    }

    pub(crate) async fn list_reconcilable(&self) -> Vec<(String, FinalDeliveryRecord)> {
        let state = self.state.lock().await;
        let mut records: Vec<_> = state
            .records
            .iter()
            .filter(|(_, record)| {
                !state.is_incomplete(&record.group_ref, &record.reply_to_ref)
                    && state
                        .turn_phase(&record.group_ref, &record.reply_to_ref)
                        .is_none_or(|phase| phase == TurnPhase::Reconcilable)
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        records.sort_by(|(_, left), (_, right)| {
            (
                &left.account_ref,
                &left.group_ref,
                &left.reply_to_ref,
                left.chunk_index,
            )
                .cmp(&(
                    &right.account_ref,
                    &right.group_ref,
                    &right.reply_to_ref,
                    right.chunk_index,
                ))
        });
        records
    }

    pub(crate) async fn set(&self, key: &str, record: FinalDeliveryRecord) -> Result<()> {
        if self.fail_next_set.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::Other).into());
        }
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        next.records.insert(key.to_owned(), record);
        self.commit(&mut state, next).await
    }

    pub(crate) async fn remove(&self, key: &str) -> Result<bool> {
        let mut state = self.state.lock().await;
        if !state.records.contains_key(key) {
            return Ok(false);
        }
        let mut next = state.clone();
        next.records.remove(key);
        self.commit(&mut state, next).await?;
        Ok(true)
    }

    pub(crate) async fn mark_incomplete_final(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        next.incomplete_finals
            .entry(group_ref.to_owned())
            .or_default()
            .insert(reply_to_ref.to_owned());
        self.commit(&mut state, next).await
    }

    /// First step of discarding the group's incomplete-final barrier and
    /// unresolved (active, limited or already discarded) turns. In one write it
    /// clears their barrier and records and leaves a `Discarded` tombstone for
    /// each reply set, so their pending artifact intents can never be replayed
    /// on a fresh budget. Call `release_discarded` once those intents are
    /// durably removed. Other groups, later complete reply sets and
    /// `keep_reply_to` are left in place. Returns the discarded reply sets.
    pub(crate) async fn begin_discard(
        &self,
        group_ref: &str,
        keep_reply_to: Option<&str>,
    ) -> Result<Vec<String>> {
        let mut state = self.state.lock().await;
        let mut discarded: HashSet<String> = state
            .incomplete_finals
            .get(group_ref)
            .cloned()
            .unwrap_or_default();
        discarded.extend(
            state
                .turn_budgets
                .values()
                .filter(|budget| {
                    budget.group_ref == group_ref && budget.phase != TurnPhase::Reconcilable
                })
                .map(|budget| budget.reply_to_ref.clone()),
        );
        if let Some(keep) = keep_reply_to {
            discarded.remove(keep);
        }
        if discarded.is_empty() {
            return Ok(Vec::new());
        }
        let mut next = state.clone();
        if let Some(reply_tos) = next.incomplete_finals.get_mut(group_ref) {
            reply_tos.retain(|reply_to| !discarded.contains(reply_to));
            if reply_tos.is_empty() {
                next.incomplete_finals.remove(group_ref);
            }
        }
        next.records.retain(|_, record| {
            record.group_ref != group_ref || !discarded.contains(&record.reply_to_ref)
        });
        for reply_to_ref in &discarded {
            next.turn_budgets
                .entry(turn_key(group_ref, reply_to_ref))
                .or_insert_with(|| TurnBudgetRecord {
                    group_ref: group_ref.to_owned(),
                    reply_to_ref: reply_to_ref.clone(),
                    max_durable_sends: 0,
                    sends_charged: 0,
                    phase: TurnPhase::Discarded,
                })
                .phase = TurnPhase::Discarded;
        }
        self.commit(&mut state, next).await?;
        let mut discarded: Vec<_> = discarded.into_iter().collect();
        discarded.sort();
        Ok(discarded)
    }

    /// Final step of a discard: removes the `Discarded` tombstones of
    /// `reply_tos` after their artifact intents are durably gone.
    pub(crate) async fn release_discarded(
        &self,
        group_ref: &str,
        reply_tos: &[String],
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        next.turn_budgets.retain(|_, budget| {
            budget.group_ref != group_ref
                || budget.phase != TurnPhase::Discarded
                || !reply_tos.contains(&budget.reply_to_ref)
        });
        self.commit(&mut state, next).await
    }

    /// Persists an active budget before the backend is spawned. A retained
    /// budget for the same turn keeps its charged sends.
    pub(crate) async fn begin_turn(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        max_durable_sends: usize,
    ) -> Result<()> {
        self.fail_injected_budget_write()?;
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        next.turn_budgets
            .entry(turn_key(group_ref, reply_to_ref))
            .or_insert_with(|| TurnBudgetRecord {
                group_ref: group_ref.to_owned(),
                reply_to_ref: reply_to_ref.to_owned(),
                max_durable_sends,
                sends_charged: 0,
                phase: TurnPhase::Active,
            })
            .phase = TurnPhase::Active;
        self.commit(&mut state, next).await
    }

    /// Durably charges one send attempt before its effect. Replay is admitted
    /// only for reconcilable turns, so stale reconciliation snapshots cannot
    /// race a live, crashed, limited or discarded turn. A legacy entry without a
    /// budget receives a fresh finite budget of `default_max` sends, so replay
    /// callers must first confirm their work item is still pending (see
    /// `reserve_record_replay`); otherwise discarded work, whose budget is gone,
    /// would look like a legacy entry. `Live` callers must already hold the
    /// active budget persisted by `begin_turn`, whose failure prevents the
    /// backend from spawning.
    pub(crate) async fn reserve_send(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        mode: SendMode,
        default_max: usize,
    ) -> Result<SendAdmission> {
        self.reserve(group_ref, reply_to_ref, mode, default_max, None)
            .await
    }

    /// Replay reservation for one staged final record. It is admitted only
    /// while `record_key` is still pending, checked under the same lock as the
    /// charge, so a stale snapshot cannot resend a record that was delivered
    /// or discarded after it was taken.
    pub(crate) async fn reserve_record_replay(
        &self,
        record_key: &str,
        group_ref: &str,
        reply_to_ref: &str,
        default_max: usize,
    ) -> Result<SendAdmission> {
        self.reserve(
            group_ref,
            reply_to_ref,
            SendMode::Replay,
            default_max,
            Some(record_key),
        )
        .await
    }

    async fn reserve(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        mode: SendMode,
        default_max: usize,
        pending_record: Option<&str>,
    ) -> Result<SendAdmission> {
        self.fail_injected_budget_write()?;
        let mut state = self.state.lock().await;
        if pending_record.is_some_and(|record_key| !state.records.contains_key(record_key)) {
            return Ok(SendAdmission::Withheld);
        }
        let key = turn_key(group_ref, reply_to_ref);
        let mut budget =
            state
                .turn_budgets
                .get(&key)
                .cloned()
                .unwrap_or_else(|| TurnBudgetRecord {
                    group_ref: group_ref.to_owned(),
                    reply_to_ref: reply_to_ref.to_owned(),
                    max_durable_sends: default_max,
                    sends_charged: 0,
                    phase: TurnPhase::Reconcilable,
                });
        let withheld = match (mode, budget.phase) {
            (_, TurnPhase::Limited | TurnPhase::Discarded) => true,
            (SendMode::Replay, TurnPhase::Active) => true,
            (SendMode::Replay, TurnPhase::Reconcilable) => {
                state.is_incomplete(group_ref, reply_to_ref)
            }
            (SendMode::Live, _) => false,
        };
        if withheld {
            return Ok(SendAdmission::Withheld);
        }
        if budget.sends_charged >= budget.max_durable_sends {
            return Ok(SendAdmission::Exhausted);
        }
        budget.sends_charged += 1;
        let mut next = state.clone();
        next.turn_budgets.insert(key, budget);
        self.commit(&mut state, next).await?;
        Ok(SendAdmission::Admitted)
    }

    /// Ends live ownership after safe collection. A turn with pending records or
    /// `keep` (pending artifact work) stays reconcilable; a clean turn is pruned.
    pub(crate) async fn finish_turn(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        keep: bool,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let key = turn_key(group_ref, reply_to_ref);
        if state.turn_phase(group_ref, reply_to_ref) != Some(TurnPhase::Active) {
            return Ok(());
        }
        let mut next = state.clone();
        if keep || next.turn_has_records(group_ref, reply_to_ref) {
            next.turn_budgets
                .get_mut(&key)
                .expect("active budget exists")
                .phase = TurnPhase::Reconcilable;
        } else {
            next.turn_budgets.remove(&key);
        }
        self.commit(&mut state, next).await
    }

    /// Marks a turn limited and records the incomplete-final barrier in one write.
    /// Pending records and acknowledgement-unknown keys are retained unchanged.
    pub(crate) async fn limit_turn(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        default_max: usize,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut next = state.clone();
        next.turn_budgets
            .entry(turn_key(group_ref, reply_to_ref))
            .or_insert_with(|| TurnBudgetRecord {
                group_ref: group_ref.to_owned(),
                reply_to_ref: reply_to_ref.to_owned(),
                max_durable_sends: default_max,
                sends_charged: 0,
                phase: TurnPhase::Limited,
            })
            .phase = TurnPhase::Limited;
        next.incomplete_finals
            .entry(group_ref.to_owned())
            .or_default()
            .insert(reply_to_ref.to_owned());
        self.commit(&mut state, next).await
    }

    /// `limit_turn` for a replay whose budget was exhausted. A discard may
    /// tombstone or release the turn between the exhausted admission and this
    /// call; that discard owns the turn, so only a turn still reconcilable or
    /// limited is marked. Returns whether the turn is limited.
    pub(crate) async fn limit_replayed_turn(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
    ) -> Result<bool> {
        let mut state = self.state.lock().await;
        if !matches!(
            state.turn_phase(group_ref, reply_to_ref),
            Some(TurnPhase::Reconcilable | TurnPhase::Limited)
        ) {
            return Ok(false);
        }
        let mut next = state.clone();
        next.turn_budgets
            .get_mut(&turn_key(group_ref, reply_to_ref))
            .expect("replayed turn budget exists")
            .phase = TurnPhase::Limited;
        next.incomplete_finals
            .entry(group_ref.to_owned())
            .or_default()
            .insert(reply_to_ref.to_owned());
        self.commit(&mut state, next).await?;
        Ok(true)
    }

    /// Removes a reconcilable budget once no records or `keep` work remain.
    pub(crate) async fn prune_turn(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
        keep: bool,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if keep
            || state.turn_phase(group_ref, reply_to_ref) != Some(TurnPhase::Reconcilable)
            || state.turn_has_records(group_ref, reply_to_ref)
        {
            return Ok(());
        }
        let mut next = state.clone();
        next.turn_budgets.remove(&turn_key(group_ref, reply_to_ref));
        self.commit(&mut state, next).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn turn_budget(
        &self,
        group_ref: &str,
        reply_to_ref: &str,
    ) -> Option<TurnBudgetRecord> {
        self.state
            .lock()
            .await
            .turn_budgets
            .get(&turn_key(group_ref, reply_to_ref))
            .cloned()
    }

    fn fail_injected_budget_write(&self) -> Result<()> {
        if self.fail_next_budget_write.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::Other).into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_set(&self) {
        self.fail_next_set.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_budget_write(&self) {
        self.fail_next_budget_write.store(true, Ordering::SeqCst);
    }

    async fn commit(
        &self,
        state: &mut tokio::sync::MutexGuard<'_, FinalDeliverySnapshot>,
        next: FinalDeliverySnapshot,
    ) -> Result<()> {
        let path = self.path.clone();
        let snapshot = next.clone();
        tokio::task::spawn_blocking(move || write_final_delivery_snapshot(&path, &snapshot))
            .await??;
        **state = next;
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        Ok(())
    }
}

fn parse_final_delivery_snapshot(bytes: &[u8]) -> Result<FinalDeliverySnapshot> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("records").is_some()
        || value.get("incomplete_finals").is_some()
        || value.get("turn_budgets").is_some()
    {
        Ok(serde_json::from_value(value)?)
    } else {
        Ok(FinalDeliverySnapshot {
            records: serde_json::from_value(value)?,
            incomplete_finals: HashMap::new(),
            turn_budgets: HashMap::new(),
        })
    }
}

fn write_final_delivery_snapshot(path: &Path, snapshot: &FinalDeliverySnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_private::create_dir_all_private(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    fs_private::write_private(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    fs_private::tighten_existing_private_file(path)?;
    Ok(())
}

fn write_recovery_snapshot(path: &Path, snapshot: &HashMap<String, RecoveryRecord>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_private::create_dir_all_private(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    fs_private::write_private(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    fs_private::tighten_existing_private_file(path)?;
    Ok(())
}

fn write_snapshot(path: &Path, snapshot: &HashMap<String, SessionRecord>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_private::create_dir_all_private(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    fs_private::write_private(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    fs_private::tighten_existing_private_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_store_persists_and_reloads_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("sessions.json");
        let home = dir.path().to_path_buf();

        {
            let store = SessionStore::load(path.clone(), &home).unwrap();
            store
                .record_session("group1", "ses_abc123".to_owned(), home.join("proj"))
                .await
                .unwrap();
            store
                .set_goal("group1", Some("ship the release".to_owned()))
                .await
                .unwrap();
        }

        let store = SessionStore::load(path.clone(), &home).unwrap();
        let record = store.get("group1").await.expect("record persisted");
        assert_eq!(record.session_id, "ses_abc123");
        assert_eq!(record.cwd, Some(home.join("proj")));
        assert_eq!(record.goal.as_deref(), Some("ship the release"));
    }

    #[tokio::test]
    async fn goal_only_records_leave_the_workdir_unselected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();

        {
            let store = SessionStore::load(path.clone(), &home).unwrap();
            store
                .set_goal("group1", Some("pick a repo later".to_owned()))
                .await
                .unwrap();
            let record = store.get("group1").await.expect("goal-only record");
            assert_eq!(record.cwd, None);
            assert_eq!(record.session_id, "");
        }

        let store = SessionStore::load(path, &home).unwrap();
        let record = store
            .get("group1")
            .await
            .expect("goal-only record reloaded");
        assert_eq!(record.cwd, None);
        assert_eq!(record.goal.as_deref(), Some("pick a repo later"));
    }

    #[tokio::test]
    async fn set_workdir_starts_a_new_epoch_and_keeps_the_goal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(path, &home).unwrap();
        store
            .record_session("group1", "ses_old".to_owned(), home.join("first"))
            .await
            .unwrap();
        store
            .set_goal("group1", Some("keep CI green".to_owned()))
            .await
            .unwrap();

        store
            .set_workdir("group1", home.join("second"))
            .await
            .unwrap();

        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "");
        assert_eq!(record.cwd, Some(home.join("second")));
        assert_eq!(record.goal.as_deref(), Some("keep CI green"));

        store.set_goal("group1", None).await.unwrap();
        assert_eq!(store.get("group1").await.unwrap().goal, None);
    }

    #[tokio::test]
    async fn session_store_resets_only_one_session_and_preserves_its_workdir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("sessions.json");
        let home = dir.path().to_path_buf();
        let first_cwd = home.join("first");
        let second_cwd = home.join("second");

        {
            let store = SessionStore::load(path.clone(), &home).unwrap();
            store
                .record_session("group1", "ses_first".to_owned(), first_cwd.clone())
                .await
                .unwrap();
            store
                .record_session("group2", "ses_second".to_owned(), second_cwd.clone())
                .await
                .unwrap();
            store
                .set_goal("group2", Some("second goal".to_owned()))
                .await
                .unwrap();

            assert!(
                store
                    .reset_session("group1", "reset-1")
                    .await
                    .unwrap()
                    .changed
            );
        }

        let store = SessionStore::load(path, &home).unwrap();
        let first = store.get("group1").await.expect("first group retained");
        assert_eq!(first.session_id, "");
        assert_eq!(first.cwd, Some(first_cwd));
        let second = store.get("group2").await.expect("second group retained");
        assert_eq!(second.session_id, "ses_second");
        assert_eq!(second.cwd, Some(second_cwd));
        assert_eq!(second.goal.as_deref(), Some("second goal"));
    }

    #[tokio::test]
    async fn reset_replay_is_durable_and_stale_observations_cannot_revive_old_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .record_session("group1", "ses_old".to_owned(), cwd.clone())
            .await
            .unwrap();

        let first = store.reset_session("group1", "message-1").await.unwrap();
        assert!(first.changed);
        assert!(!first.replayed);
        assert_eq!(store.get("group1").await.unwrap().generation, 1);
        assert!(
            !store
                .record_session_if_generation("group1", 0, "ses_stale".to_owned(), cwd.clone())
                .await
                .unwrap()
        );
        assert!(
            store
                .record_session_if_generation("group1", 1, "ses_after_m1".to_owned(), cwd.clone(),)
                .await
                .unwrap()
        );
        let second = store.reset_session("group1", "message-2").await.unwrap();
        assert!(second.changed);
        assert!(!second.replayed);
        assert_eq!(store.get("group1").await.unwrap().generation, 2);
        assert!(
            store
                .record_session_if_generation("group1", 2, "ses_after_m2".to_owned(), cwd.clone(),)
                .await
                .unwrap()
        );
        drop(store);

        let store = SessionStore::load(path, &home).unwrap();
        let replay = store.reset_session("group1", "message-1").await.unwrap();
        assert!(replay.changed);
        assert!(replay.replayed);
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_after_m2");
        assert_eq!(record.generation, 2);
    }

    #[tokio::test]
    async fn reset_replay_remains_idempotent_after_many_later_resets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .record_session("group1", "ses_initial".to_owned(), cwd.clone())
            .await
            .unwrap();

        for index in 0..65 {
            let message_ref = format!("message-{index}");
            let outcome = store.reset_session("group1", &message_ref).await.unwrap();
            assert!(outcome.changed);
            assert!(!outcome.replayed);
            store
                .record_session_if_generation(
                    "group1",
                    index + 1,
                    format!("ses_after_{index}"),
                    cwd.clone(),
                )
                .await
                .unwrap();
        }
        drop(store);

        let store = SessionStore::load(path, &home).unwrap();
        let replay = store.reset_session("group1", "message-0").await.unwrap();
        assert!(replay.changed);
        assert!(replay.replayed);
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_after_64");
        assert_eq!(record.generation, 65);
    }

    #[tokio::test]
    async fn empty_reset_reference_never_collapses_distinct_commands() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path, &home).unwrap();
        store
            .record_session("group1", "ses_first".to_owned(), cwd.clone())
            .await
            .unwrap();

        let first = store.reset_session("group1", "").await.unwrap();
        assert!(first.changed);
        assert!(!first.replayed);
        assert!(
            store
                .record_session_if_generation("group1", 1, "ses_second".to_owned(), cwd)
                .await
                .unwrap()
        );
        let second = store.reset_session("group1", "").await.unwrap();
        assert!(second.changed);
        assert!(!second.replayed);
        let record = store.get("group1").await.unwrap();
        assert!(record.session_id.is_empty());
        assert_eq!(record.generation, 2);
    }

    #[tokio::test]
    async fn failed_reset_keeps_the_memory_and_durable_snapshots_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .record_session("group1", "ses_original".to_owned(), cwd.clone())
            .await
            .unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();

        assert!(store.reset_session("group1", "reset-1").await.is_err());
        assert!(
            store
                .set_goal("group1", Some("g".to_owned()))
                .await
                .is_err()
        );
        assert!(
            store
                .set_workdir("group1", home.join("other"))
                .await
                .is_err()
        );
        assert!(
            store
                .record_session("group1", "ses_other".to_owned(), home.join("other"))
                .await
                .is_err()
        );
        let current = store.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_original");
        assert_eq!(current.cwd, Some(cwd.clone()));
        assert_eq!(current.goal, None);
        drop(store);

        let reloaded = SessionStore::load(path, &home).unwrap();
        let current = reloaded.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_original");
        assert_eq!(current.cwd, Some(cwd));
        assert_eq!(current.goal, None);
    }

    #[tokio::test]
    async fn session_store_accepts_bare_string_legacy_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let legacy = serde_json::json!({ "group1": "ses_legacy" });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let store = SessionStore::load(path, &home).unwrap();
        let record = store.get("group1").await.expect("legacy record");
        assert_eq!(record.session_id, "ses_legacy");
        assert_eq!(record.cwd, Some(home));
        assert_eq!(record.goal, None);
    }

    #[tokio::test]
    async fn session_store_accepts_records_written_before_the_goal_field_existed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let legacy = serde_json::json!({
            "group1": { "session_id": "ses_full", "cwd": home.join("proj") }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let store = SessionStore::load(path, &home).unwrap();
        let record = store.get("group1").await.expect("legacy full record");
        assert_eq!(record.session_id, "ses_full");
        assert_eq!(record.cwd, Some(home.join("proj")));
        assert_eq!(record.goal, None);
    }

    #[tokio::test]
    async fn recovery_store_persists_and_consumes_retry_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.json");
        let record = RecoveryRecord {
            prompt: "private prompt".to_owned(),
            media: Vec::new(),
            cwd: dir.path().join("repo"),
            session_id: "session".to_owned(),
            kind: RecoveryKind::UncertainOutcome,
            status: RecoveryStatus::Pending,
        };
        RecoveryStore::load(path.clone())
            .unwrap()
            .set("group", record.clone())
            .await
            .unwrap();

        let store = RecoveryStore::load(path.clone()).unwrap();
        assert!(store.get("group").await == Some(record));
        let first = store.begin_retry("group").await.unwrap().unwrap();
        assert_eq!(first.status, RecoveryStatus::Retrying);
        assert!(store.begin_retry("group").await.unwrap().is_none());
        assert!(store.reset_retry("group").await.unwrap());
        assert_eq!(
            store.get("group").await.unwrap().status,
            RecoveryStatus::Pending
        );
        assert!(store.begin_retry("group").await.unwrap().is_some());
        drop(store);

        let store = RecoveryStore::load(path).unwrap();
        assert_eq!(
            store.get("group").await.unwrap().status,
            RecoveryStatus::Pending
        );
        assert!(store.begin_retry("group").await.unwrap().is_some());
        assert!(store.discard("group").await.unwrap());
        assert!(store.get("group").await.is_none());
    }

    #[tokio::test]
    async fn discard_is_idempotent_and_never_replays() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecoveryStore::load(dir.path().join("recovery.json")).unwrap();
        assert!(!store.discard("missing").await.unwrap());
    }

    #[tokio::test]
    async fn final_delivery_store_survives_restart_until_reconciled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let first = FinalDeliveryRecord {
            account_ref: "account".to_owned(),
            group_ref: "group".to_owned(),
            reply_to_ref: "message".to_owned(),
            text: "first".to_owned(),
            chunk_index: 1,
        };
        let second = FinalDeliveryRecord {
            text: "second".to_owned(),
            chunk_index: 2,
            ..first.clone()
        };
        let initial = FinalDeliveryStore::load(path.clone()).unwrap();
        initial.set("second", second.clone()).await.unwrap();
        initial.set("first", first.clone()).await.unwrap();
        let store = FinalDeliveryStore::load(path).unwrap();
        let mut changed = store.subscribe();
        assert!(store.has_group("group").await);
        assert!(!store.has_group("other-group").await);
        assert!(
            store.list().await == vec![("first".to_owned(), first), ("second".to_owned(), second),]
        );
        assert!(store.remove("first").await.unwrap());
        changed.changed().await.unwrap();
        assert!(store.has_group("group").await);
        assert!(store.remove("second").await.unwrap());
        changed.changed().await.unwrap();
        assert!(!store.has_group("group").await);
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn incomplete_final_barrier_survives_restart_and_blocks_reconcile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let first = FinalDeliveryRecord {
            account_ref: "account".to_owned(),
            group_ref: "group".to_owned(),
            reply_to_ref: "message".to_owned(),
            text: "first".to_owned(),
            chunk_index: 0,
        };
        let store = FinalDeliveryStore::load(path.clone()).unwrap();
        store.set("first", first.clone()).await.unwrap();
        store.fail_next_set();
        assert!(
            store
                .set(
                    "second",
                    FinalDeliveryRecord {
                        text: "second".to_owned(),
                        chunk_index: 1,
                        ..first.clone()
                    },
                )
                .await
                .is_err()
        );
        store
            .mark_incomplete_final("group", "message")
            .await
            .unwrap();
        drop(store);

        let store = FinalDeliveryStore::load(path).unwrap();
        assert!(store.has_incomplete_final("group").await);
        assert!(store.blocks_group("group").await);
        assert_eq!(store.list().await.len(), 1);
        assert!(store.list_reconcilable().await.is_empty());
        assert_eq!(
            discard(&store, "group", None).await,
            vec!["message".to_owned()]
        );
        assert!(!store.has_incomplete_final("group").await);
        assert!(!store.blocks_group("group").await);
        assert!(store.list().await.is_empty());
        assert!(discard(&store, "group", None).await.is_empty());
    }

    /// Both discard steps, as the bridge runs them for a turn with no
    /// pending artifact intents.
    async fn discard(
        store: &FinalDeliveryStore,
        group_ref: &str,
        keep_reply_to: Option<&str>,
    ) -> Vec<String> {
        let discarded = store.begin_discard(group_ref, keep_reply_to).await.unwrap();
        store
            .release_discarded(group_ref, &discarded)
            .await
            .unwrap();
        discarded
    }

    fn delivery_record(reply_to_ref: &str, chunk_index: usize) -> FinalDeliveryRecord {
        FinalDeliveryRecord {
            account_ref: "account".to_owned(),
            group_ref: "group".to_owned(),
            reply_to_ref: reply_to_ref.to_owned(),
            text: format!("chunk {chunk_index}"),
            chunk_index,
        }
    }

    #[tokio::test]
    async fn turn_budget_charges_each_attempt_and_exhausts_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = FinalDeliveryStore::load(dir.path().join("delivery.json")).unwrap();
        store.begin_turn("group", "message", 2).await.unwrap();
        assert!(store.blocks_group("group").await);
        for _ in 0..2 {
            assert_eq!(
                store
                    .reserve_send("group", "message", SendMode::Live, 99)
                    .await
                    .unwrap(),
                SendAdmission::Admitted
            );
        }
        assert_eq!(
            store
                .reserve_send("group", "message", SendMode::Live, 99)
                .await
                .unwrap(),
            SendAdmission::Exhausted
        );
        let budget = store.turn_budget("group", "message").await.unwrap();
        assert_eq!((budget.sends_charged, budget.max_durable_sends), (2, 2));
        let debug = format!("{budget:?}");
        assert!(!debug.contains("group") && !debug.contains("message"));
    }

    #[tokio::test]
    async fn interrupted_and_limited_turns_survive_restart_block_group_and_withhold_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        {
            let store = FinalDeliveryStore::load(path.clone()).unwrap();
            store.begin_turn("group", "active", 8).await.unwrap();
            store
                .set("active:1", delivery_record("active", 1))
                .await
                .unwrap();
            assert_eq!(
                store
                    .reserve_send("group", "active", SendMode::Live, 8)
                    .await
                    .unwrap(),
                SendAdmission::Admitted
            );
            store.begin_turn("group", "limited", 8).await.unwrap();
            store
                .set("limited:1", delivery_record("limited", 1))
                .await
                .unwrap();
            store.limit_turn("group", "limited", 8).await.unwrap();
            assert!(!store.requires_recovery_command("other").await);
        }

        let store = FinalDeliveryStore::load(path).unwrap();
        assert!(store.blocks_group("group").await);
        assert!(store.requires_recovery_command("group").await);
        assert!(store.has_incomplete_final("group").await);
        assert!(store.list_reconcilable().await.is_empty());
        let interrupted = store.turn_budget("group", "active").await.unwrap();
        assert_eq!(interrupted.phase, TurnPhase::Limited);
        assert_eq!(
            (interrupted.sends_charged, interrupted.max_durable_sends),
            (1, 8)
        );
        for reply_to in ["active", "limited"] {
            for mode in [SendMode::Replay, SendMode::Live] {
                assert_eq!(
                    store
                        .reserve_send("group", reply_to, mode, 8)
                        .await
                        .unwrap(),
                    SendAdmission::Withheld
                );
            }
        }
        assert_eq!(store.list().await.len(), 2);
        assert_eq!(
            discard(&store, "group", None).await,
            vec!["active".to_owned(), "limited".to_owned()]
        );
        assert!(!store.blocks_group("group").await);
        assert!(store.list().await.is_empty());
        assert!(store.turn_budget("group", "active").await.is_none());
        assert!(store.turn_budget("group", "limited").await.is_none());
    }

    #[tokio::test]
    async fn turn_interrupted_before_any_record_loads_as_a_discardable_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        {
            let store = FinalDeliveryStore::load(path.clone()).unwrap();
            store.begin_turn("group", "active", 8).await.unwrap();
            store.begin_turn("group", "done", 8).await.unwrap();
            store
                .set("done:1", delivery_record("done", 1))
                .await
                .unwrap();
            store.finish_turn("group", "done", false).await.unwrap();
        }

        let store = FinalDeliveryStore::load(path.clone()).unwrap();
        assert_eq!(store.list().await.len(), 1);
        assert_eq!(
            store.turn_budget("group", "active").await.unwrap().phase,
            TurnPhase::Limited
        );
        assert_eq!(
            store.turn_budget("group", "done").await.unwrap().phase,
            TurnPhase::Reconcilable
        );
        assert!(store.requires_recovery_command("group").await);
        // A turn that finished before the restart stays reconcilable.
        assert_eq!(store.list_reconcilable().await.len(), 1);

        // Normalization is idempotent across repeated restarts.
        drop(store);
        let store = FinalDeliveryStore::load(path).unwrap();
        assert_eq!(
            store.turn_budget("group", "active").await.unwrap().phase,
            TurnPhase::Limited
        );
        // A live turn in the group, such as a running retry, is not waiting on
        // a recovery command.
        store.begin_turn("group", "retry", 8).await.unwrap();
        assert!(!store.requires_recovery_command("group").await);
        store.finish_turn("group", "retry", false).await.unwrap();
        assert!(store.requires_recovery_command("group").await);
        assert_eq!(
            discard(&store, "group", None).await,
            vec!["active".to_owned()]
        );
        assert!(!store.requires_recovery_command("group").await);
        assert!(store.turn_budget("group", "active").await.is_none());
        assert_eq!(store.list().await.len(), 1);
    }

    #[tokio::test]
    async fn turn_budgets_are_rekeyed_from_their_identity_on_load() {
        assert_ne!(turn_key("a:b", "c"), turn_key("a", "b:c"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let snapshot = serde_json::json!({
            "turn_budgets": {
                "group:message": {
                    "group_ref": "group",
                    "reply_to_ref": "message",
                    "max_durable_sends": 3,
                    "sends_charged": 3,
                    "phase": "reconcilable"
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();

        let store = FinalDeliveryStore::load(path).unwrap();
        assert_eq!(
            store
                .reserve_send("group", "message", SendMode::Replay, 99)
                .await
                .unwrap(),
            SendAdmission::Exhausted
        );
    }

    #[tokio::test]
    async fn finished_turns_keep_budget_across_reconciliation_and_prune_when_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let store = FinalDeliveryStore::load(path.clone()).unwrap();
        store.begin_turn("group", "clean", 4).await.unwrap();
        store.finish_turn("group", "clean", false).await.unwrap();
        assert!(store.turn_budget("group", "clean").await.is_none());

        store.begin_turn("group", "pending", 2).await.unwrap();
        store
            .set("pending:1", delivery_record("pending", 1))
            .await
            .unwrap();
        assert_eq!(
            store
                .reserve_send("group", "pending", SendMode::Live, 2)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        store.finish_turn("group", "pending", false).await.unwrap();
        drop(store);

        let store = FinalDeliveryStore::load(path).unwrap();
        assert_eq!(store.list_reconcilable().await.len(), 1);
        assert_eq!(
            store
                .reserve_send("group", "pending", SendMode::Replay, 99)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        assert_eq!(
            store
                .reserve_send("group", "pending", SendMode::Replay, 99)
                .await
                .unwrap(),
            SendAdmission::Exhausted
        );
        store.prune_turn("group", "pending", false).await.unwrap();
        assert!(store.turn_budget("group", "pending").await.is_some());
        assert!(store.remove("pending:1").await.unwrap());
        store.prune_turn("group", "pending", true).await.unwrap();
        assert!(store.turn_budget("group", "pending").await.is_some());
        store.prune_turn("group", "pending", false).await.unwrap();
        assert!(store.turn_budget("group", "pending").await.is_none());
    }

    #[tokio::test]
    async fn legacy_entries_receive_a_finite_budget_before_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let legacy = serde_json::json!({
            "records": { "legacy:1": delivery_record("legacy", 1) },
            "incomplete_finals": {}
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let store = FinalDeliveryStore::load(path).unwrap();
        assert_eq!(store.list_reconcilable().await.len(), 1);
        assert_eq!(
            store
                .reserve_send("group", "legacy", SendMode::Replay, 1)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        let budget = store.turn_budget("group", "legacy").await.unwrap();
        assert_eq!(budget.phase, TurnPhase::Reconcilable);
        assert_eq!((budget.sends_charged, budget.max_durable_sends), (1, 1));
        assert_eq!(
            store
                .reserve_send("group", "legacy", SendMode::Replay, 1)
                .await
                .unwrap(),
            SendAdmission::Exhausted
        );
    }

    #[tokio::test]
    async fn failed_budget_writes_fail_closed_without_charging_or_admitting() {
        let dir = tempfile::tempdir().unwrap();
        let store = FinalDeliveryStore::load(dir.path().join("delivery.json")).unwrap();
        store.fail_next_budget_write();
        assert!(store.begin_turn("group", "message", 2).await.is_err());
        assert!(store.turn_budget("group", "message").await.is_none());
        store.begin_turn("group", "message", 2).await.unwrap();
        store.fail_next_budget_write();
        assert!(
            store
                .reserve_send("group", "message", SendMode::Live, 2)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .turn_budget("group", "message")
                .await
                .unwrap()
                .sends_charged,
            0
        );
    }

    #[tokio::test]
    async fn discard_keeps_the_named_reply_set() {
        let dir = tempfile::tempdir().unwrap();
        let store = FinalDeliveryStore::load(dir.path().join("delivery.json")).unwrap();
        store.begin_turn("group", "old", 4).await.unwrap();
        store.limit_turn("group", "old", 4).await.unwrap();
        store.begin_turn("group", "current", 4).await.unwrap();
        assert_eq!(
            discard(&store, "group", Some("current")).await,
            vec!["old".to_owned()]
        );
        assert_eq!(
            store.turn_budget("group", "current").await.unwrap().phase,
            TurnPhase::Active
        );
    }

    #[tokio::test]
    async fn discarded_turn_stays_withheld_and_blocking_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let store = FinalDeliveryStore::load(path.clone()).unwrap();
        store.begin_turn("group", "limited", 1).await.unwrap();
        store
            .set("limited:1", delivery_record("limited", 1))
            .await
            .unwrap();
        assert_eq!(
            store
                .reserve_send("group", "limited", SendMode::Live, 1)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        store.limit_turn("group", "limited", 1).await.unwrap();
        // A barrier-only reply set without any budget also gets a tombstone.
        store
            .mark_incomplete_final("group", "barrier")
            .await
            .unwrap();

        assert_eq!(
            store.begin_discard("group", None).await.unwrap(),
            vec!["barrier".to_owned(), "limited".to_owned()]
        );
        drop(store);
        let store = FinalDeliveryStore::load(path).unwrap();
        assert!(store.list().await.is_empty());
        assert!(!store.has_incomplete_final("group").await);
        assert!(store.blocks_group("group").await);
        assert!(store.requires_recovery_command("group").await);
        for reply_to in ["limited", "barrier"] {
            assert_eq!(
                store.turn_budget("group", reply_to).await.unwrap().phase,
                TurnPhase::Discarded
            );
            for mode in [SendMode::Replay, SendMode::Live] {
                assert_eq!(
                    store
                        .reserve_send("group", reply_to, mode, 8)
                        .await
                        .unwrap(),
                    SendAdmission::Withheld
                );
            }
        }
        // The original accounting is retained, not replaced by a fresh budget.
        let limited = store.turn_budget("group", "limited").await.unwrap();
        assert_eq!((limited.sends_charged, limited.max_durable_sends), (1, 1));

        // A repeated discard resumes the tombstoned reply sets.
        assert_eq!(
            discard(&store, "group", None).await,
            vec!["barrier".to_owned(), "limited".to_owned()]
        );
        assert!(!store.blocks_group("group").await);
        assert!(!store.requires_recovery_command("group").await);
        assert!(store.turn_budget("group", "limited").await.is_none());
    }

    #[tokio::test]
    async fn exhausted_replay_limits_only_a_turn_not_owned_by_a_discard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let store = FinalDeliveryStore::load(path.clone()).unwrap();
        store.begin_turn("group", "turn", 1).await.unwrap();
        for chunk in [1, 2] {
            store
                .set(&format!("turn:{chunk}"), delivery_record("turn", chunk))
                .await
                .unwrap();
        }
        store.finish_turn("group", "turn", false).await.unwrap();
        assert_eq!(
            store
                .reserve_record_replay("turn:1", "group", "turn", 8)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        // Two concurrent replays of the turn both find its budget exhausted.
        for key in ["turn:1", "turn:2"] {
            assert_eq!(
                store
                    .reserve_record_replay(key, "group", "turn", 8)
                    .await
                    .unwrap(),
                SendAdmission::Exhausted
            );
        }
        assert!(store.limit_replayed_turn("group", "turn").await.unwrap());
        assert_eq!(
            store.turn_budget("group", "turn").await.unwrap().phase,
            TurnPhase::Limited
        );
        assert!(store.has_incomplete_final("group").await);

        // A discard tombstones the turn before the second replay records its
        // limit, which must not turn the tombstone back into a limited turn.
        let discarded = store.begin_discard("group", None).await.unwrap();
        assert_eq!(discarded, vec!["turn".to_owned()]);
        assert!(!store.limit_replayed_turn("group", "turn").await.unwrap());
        let tombstone = store.turn_budget("group", "turn").await.unwrap();
        assert_eq!(tombstone.phase, TurnPhase::Discarded);
        assert_eq!(
            (tombstone.sends_charged, tombstone.max_durable_sends),
            (1, 1)
        );
        assert!(!store.has_incomplete_final("group").await);

        // A limit recorded after the release neither recreates the turn nor
        // re-blocks the group whose discard reported it released.
        store.release_discarded("group", &discarded).await.unwrap();
        assert!(!store.limit_replayed_turn("group", "turn").await.unwrap());
        drop(store);
        let store = FinalDeliveryStore::load(path).unwrap();
        assert!(store.turn_budget("group", "turn").await.is_none());
        assert!(store.list().await.is_empty());
        assert!(!store.has_incomplete_final("group").await);
        assert!(!store.blocks_group("group").await);
        assert!(!store.requires_recovery_command("group").await);
    }

    #[tokio::test]
    async fn record_replay_is_admitted_only_while_the_record_is_pending() {
        let dir = tempfile::tempdir().unwrap();
        let store = FinalDeliveryStore::load(dir.path().join("delivery.json")).unwrap();
        store
            .set("legacy:1", delivery_record("legacy", 1))
            .await
            .unwrap();
        assert_eq!(
            store
                .reserve_record_replay("legacy:1", "group", "legacy", 2)
                .await
                .unwrap(),
            SendAdmission::Admitted
        );
        assert!(store.remove("legacy:1").await.unwrap());
        assert_eq!(
            store
                .reserve_record_replay("legacy:1", "group", "legacy", 2)
                .await
                .unwrap(),
            SendAdmission::Withheld
        );
        assert_eq!(
            store
                .turn_budget("group", "legacy")
                .await
                .unwrap()
                .sends_charged,
            1
        );
        // A record removed by a completed discard never mints a fresh budget.
        assert_eq!(
            store
                .reserve_record_replay("gone:1", "group", "gone", 2)
                .await
                .unwrap(),
            SendAdmission::Withheld
        );
        assert!(store.turn_budget("group", "gone").await.is_none());
    }

    #[tokio::test]
    async fn final_delivery_store_loads_legacy_bare_record_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.json");
        let legacy = serde_json::json!({
            "first": {
                "account_ref": "account",
                "group_ref": "group",
                "reply_to_ref": "message",
                "text": "first",
                "chunk_index": 0
            }
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let store = FinalDeliveryStore::load(path).unwrap();
        assert!(store.has_group("group").await);
        assert!(!store.has_incomplete_final("group").await);
        assert_eq!(store.list().await.len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_store_creates_private_parent_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("sessions.json");
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .record_session("group1", "ses_private".to_owned(), home)
            .await
            .unwrap();
        assert!(
            store
                .reset_session("group1", "reset-1")
                .await
                .unwrap()
                .changed
        );

        let parent_mode = path
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = path.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, fs_private::PRIVATE_DIR_MODE);
        assert_eq!(file_mode, fs_private::PRIVATE_FILE_MODE);
    }
}
