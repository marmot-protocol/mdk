use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};

use crate::error::Result;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) session_id: String,
    pub(crate) cwd: PathBuf,
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
    Full { session_id: String, cwd: PathBuf },
}

impl RawRecord {
    fn into_record(self, default_cwd: &Path) -> SessionRecord {
        match self {
            Self::Bare(session_id) => SessionRecord {
                session_id,
                cwd: default_cwd.to_path_buf(),
            },
            Self::Full { session_id, cwd } => SessionRecord { session_id, cwd },
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

    pub(crate) async fn set(&self, group_key: &str, record: SessionRecord) -> Result<()> {
        let mut map = self.map.lock().await;
        let mut next = map.clone();
        next.insert(group_key.to_owned(), record);
        let path = self.path.clone();
        let snapshot = next.clone();
        tokio::task::spawn_blocking(move || write_snapshot(&path, &snapshot)).await??;
        *map = next;
        Ok(())
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
        let path = self.path.clone();
        let snapshot = next.clone();
        tokio::task::spawn_blocking(move || write_snapshot(&path, &snapshot)).await??;
        *map = next;
        Ok(true)
    }
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

pub(crate) struct FinalDeliveryStore {
    path: PathBuf,
    map: Mutex<HashMap<String, FinalDeliveryRecord>>,
    changed: watch::Sender<u64>,
}

impl FinalDeliveryStore {
    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        if path.exists() {
            fs_private::tighten_existing_private_file(&path)?;
        }
        let map = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes)?,
            Ok(_) => HashMap::new(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => return Err(err.into()),
        };
        let (changed, _) = watch::channel(0);
        Ok(Self {
            path,
            map: Mutex::new(map),
            changed,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub(crate) async fn has_group(&self, group_ref: &str) -> bool {
        self.map
            .lock()
            .await
            .values()
            .any(|record| record.group_ref == group_ref)
    }

    pub(crate) async fn list(&self) -> Vec<(String, FinalDeliveryRecord)> {
        let mut records: Vec<_> = self
            .map
            .lock()
            .await
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

    pub(crate) async fn set(&self, key: &str, record: FinalDeliveryRecord) -> Result<()> {
        let mut map = self.map.lock().await;
        let mut next = map.clone();
        next.insert(key.to_owned(), record);
        self.commit(&mut map, next).await?;
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        Ok(())
    }

    pub(crate) async fn remove(&self, key: &str) -> Result<bool> {
        let mut map = self.map.lock().await;
        if !map.contains_key(key) {
            return Ok(false);
        }
        let mut next = map.clone();
        next.remove(key);
        self.commit(&mut map, next).await?;
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        Ok(true)
    }

    async fn commit(
        &self,
        map: &mut tokio::sync::MutexGuard<'_, HashMap<String, FinalDeliveryRecord>>,
        next: HashMap<String, FinalDeliveryRecord>,
    ) -> Result<()> {
        let path = self.path.clone();
        let snapshot = next.clone();
        tokio::task::spawn_blocking(move || write_final_delivery_snapshot(&path, &snapshot))
            .await??;
        **map = next;
        Ok(())
    }
}

fn write_final_delivery_snapshot(
    path: &Path,
    snapshot: &HashMap<String, FinalDeliveryRecord>,
) -> Result<()> {
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
            let record = SessionRecord {
                session_id: "ses_abc123".to_owned(),
                cwd: home.join("proj"),
            };
            store.set("group1", record).await.unwrap();
        }

        let store = SessionStore::load(path.clone(), &home).unwrap();
        let record = store.get("group1").await.expect("record persisted");
        assert_eq!(record.session_id, "ses_abc123");
        assert_eq!(record.cwd, home.join("proj"));
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
                .set(
                    "group1",
                    SessionRecord {
                        session_id: "ses_first".to_owned(),
                        cwd: first_cwd.clone(),
                    },
                )
                .await
                .unwrap();
            store
                .set(
                    "group2",
                    SessionRecord {
                        session_id: "ses_second".to_owned(),
                        cwd: second_cwd.clone(),
                    },
                )
                .await
                .unwrap();

            assert!(store.reset_session("group1").await.unwrap());
        }

        let store = SessionStore::load(path, &home).unwrap();
        let first = store.get("group1").await.expect("first group retained");
        assert_eq!(first.session_id, "");
        assert_eq!(first.cwd, first_cwd);
        let second = store.get("group2").await.expect("second group retained");
        assert_eq!(second.session_id, "ses_second");
        assert_eq!(second.cwd, second_cwd);
    }

    #[tokio::test]
    async fn failed_reset_keeps_the_memory_and_durable_snapshots_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .set(
                "group1",
                SessionRecord {
                    session_id: "ses_original".to_owned(),
                    cwd: cwd.clone(),
                },
            )
            .await
            .unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();

        assert!(store.reset_session("group1").await.is_err());
        let current = store.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_original");
        assert_eq!(current.cwd, cwd);
        drop(store);

        let reloaded = SessionStore::load(path, &home).unwrap();
        let current = reloaded.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_original");
        assert_eq!(current.cwd, cwd);
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
        assert_eq!(record.cwd, home);
    }

    #[tokio::test]
    async fn recovery_store_persists_and_consumes_retry_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.json");
        let record = RecoveryRecord {
            prompt: "private prompt".to_owned(),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn session_store_creates_private_parent_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("sessions.json");
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(path.clone(), &home).unwrap();
        store
            .set(
                "group1",
                SessionRecord {
                    session_id: "ses_private".to_owned(),
                    cwd: home,
                },
            )
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
