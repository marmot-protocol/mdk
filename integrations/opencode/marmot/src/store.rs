use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::Result;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) session_id: String,
    pub(crate) cwd: PathBuf,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug)]
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
