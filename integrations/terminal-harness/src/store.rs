use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use agent_control::AgentControlMediaRef;
use serde::{Deserialize, Serialize};
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
    },
}

impl RawRecord {
    fn into_record(self, default_cwd: &Path) -> SessionRecord {
        match self {
            Self::Bare(session_id) => SessionRecord {
                session_id,
                cwd: Some(default_cwd.to_path_buf()),
                goal: None,
            },
            Self::Full {
                session_id,
                cwd,
                goal,
            } => SessionRecord {
                session_id,
                cwd,
                goal,
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

    /// Selects the working directory and starts a new session epoch, retaining
    /// the goal.
    pub(crate) async fn set_workdir(&self, group_key: &str, cwd: PathBuf) -> Result<()> {
        self.update(group_key, |record| {
            record.session_id.clear();
            record.cwd = Some(cwd);
        })
        .await
    }

    /// Replaces the standing goal, retaining the session and working directory.
    pub(crate) async fn set_goal(&self, group_key: &str, goal: Option<String>) -> Result<()> {
        self.update(group_key, |record| record.goal = goal).await
    }

    pub(crate) async fn reset_session(&self, group_key: &str) -> Result<bool> {
        let mut map = self.map.lock().await;
        let Some(record) = map.get(group_key) else {
            return Ok(false);
        };
        if record.session_id.is_empty() {
            return Ok(false);
        }

        let mut next = map.clone();
        next.get_mut(group_key)
            .expect("record exists in cloned session map")
            .session_id
            .clear();
        persist(&self.path, &mut map, next).await?;
        Ok(true)
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
    records: HashMap<String, FinalDeliveryRecord>,
    #[serde(default)]
    incomplete_finals: HashMap<String, HashSet<String>>,
}

pub(crate) struct FinalDeliveryStore {
    path: PathBuf,
    state: Mutex<FinalDeliverySnapshot>,
    changed: watch::Sender<u64>,
    fail_next_set: AtomicBool,
}

impl FinalDeliveryStore {
    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        if path.exists() {
            fs_private::tighten_existing_private_file(&path)?;
        }
        let state = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => parse_final_delivery_snapshot(&bytes)?,
            Ok(_) => FinalDeliverySnapshot::default(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                FinalDeliverySnapshot::default()
            }
            Err(err) => return Err(err.into()),
        };
        let (changed, _) = watch::channel(0);
        Ok(Self {
            path,
            state: Mutex::new(state),
            changed,
            fail_next_set: AtomicBool::new(false),
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

    pub(crate) async fn blocks_group(&self, group_ref: &str) -> bool {
        self.has_incomplete_final(group_ref).await || self.has_group(group_ref).await
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
                !state
                    .incomplete_finals
                    .get(&record.group_ref)
                    .is_some_and(|reply_tos| reply_tos.contains(&record.reply_to_ref))
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

    /// Clears the group's incomplete-final barrier and removes only the records
    /// that belong to those incomplete reply sets. Other groups and later
    /// complete reply sets are left in place.
    pub(crate) async fn discard_incomplete_final(&self, group_ref: &str) -> Result<bool> {
        let mut state = self.state.lock().await;
        if state
            .incomplete_finals
            .get(group_ref)
            .is_none_or(|reply_tos| reply_tos.is_empty())
        {
            return Ok(false);
        }
        let mut next = state.clone();
        let reply_tos = next.incomplete_finals.remove(group_ref).unwrap_or_default();
        next.records.retain(|_, record| {
            record.group_ref != group_ref || !reply_tos.contains(&record.reply_to_ref)
        });
        self.commit(&mut state, next).await?;
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_set(&self) {
        self.fail_next_set.store(true, Ordering::SeqCst);
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
    if value.get("records").is_some() || value.get("incomplete_finals").is_some() {
        Ok(serde_json::from_value(value)?)
    } else {
        Ok(FinalDeliverySnapshot {
            records: serde_json::from_value(value)?,
            incomplete_finals: HashMap::new(),
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

            assert!(store.reset_session("group1").await.unwrap());
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

        assert!(store.reset_session("group1").await.is_err());
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
        assert!(store.discard_incomplete_final("group").await.unwrap());
        assert!(!store.has_incomplete_final("group").await);
        assert!(!store.blocks_group("group").await);
        assert!(store.list().await.is_empty());
        assert!(!store.discard_incomplete_final("group").await.unwrap());
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
        assert!(store.reset_session("group1").await.unwrap());

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
