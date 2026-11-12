//! Per-group write counts behind `StorageProvider::group_write_generation`
//! (mdk#3273).
//!
//! TEMP triggers on every table a published group answer reads call back
//! into a count for the group, so no write path, cascade, snapshot restore or
//! wipe can change an input without moving its group's count. SQLite runs row
//! triggers for every row a statement writes, cascaded and unkeyed deletes
//! included; the one write it runs no trigger for, the row a REPLACE deletes,
//! is counted before the write by a trigger per unique key that leaves out the
//! group column. `every_write_into_a_covered_table_is_counted` checks the
//! schema keeps it that way.
//!
//! The counts are kept per database file, by its identity rather than its
//! path, and shared by every connection this process opens on it: the
//! engine's connection and the app's cached one write the same tables
//! (mdk#2323).
//!
//! A trigger fires inside the statement that writes the row, before the
//! write is visible to any other connection. Its note waits on its own
//! connection and joins the file's counts when that connection is released
//! outside a transaction, so its write is committed and visible first: a
//! count read before an answer is built never names state the answer cannot
//! see. A rolled-back write is still counted; that costs a rebuild, never a
//! stale answer.
//!
//! Writers the triggers do not see (another process, a raw connection) are
//! caught by `PRAGMA data_version`: reading the write count checks it, and a
//! move no counted commit explains moves every group, and is reported (a
//! warning, a panic under test) unless one of this process's counted
//! connections made a move SQLite makes without a commit: a WAL truncate, a
//! `VACUUM`, a rollback (see [`GroupWriteCounter::check_unexplained_commits`]).
//!
//! Two scopes: `committed` moves on the group record and its commit-derived
//! OpenMLS rows; `state` moves on those and every other input. Application
//! message ratchet rows (`MessageSecrets`, `ApplicationExportTree`) and message
//! rows that are not withdrawn commits move neither, so ingesting an
//! application message leaves a group's answers cached.

use crate::SqliteResultExt;
use crate::base::codec::message_state_to_i64;
use crate::base::connection::{
    ConnectionHooks, HooklessMove, SharedConnection, WeakSharedConnection,
};
use crate::protocol::openmls_storage::ratchet_labels;
use cgka_traits::message::MessageState;
use cgka_traits::storage::{GroupWriteGeneration, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use rusqlite::types::ValueRef;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};

/// The scalar function every trigger calls: `(scope, key_kind, key)`.
const FUNCTION: &str = "mdk_group_written";

/// Scopes the triggers pass.
const STATE: i64 = 0;
const COMMITTED: i64 = 1;

/// How a trigger names its group.
const RAW_ID: i64 = 0;
const HEX_ID: i64 = 1;
const OPENMLS_GROUP_KEY: i64 = 2;
/// A write this counter cannot attribute to one group: it moves every group.
const EVERY_GROUP: i64 = 3;

/// One database file's counts, by file identity, while a connection to it is
/// open.
static FILES: LazyLock<Mutex<HashMap<FileKey, Weak<Mutex<Counts>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Database files a test writes through a connection of its own, by
/// [`declared_path`]; see [`expect_uncounted_writes_for_test`].
#[cfg(any(test, feature = "test-support"))]
static UNCOUNTED_WRITERS: LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

/// Declare that this test writes the database at `path` through a
/// connection of its own (a fault trigger, a raw row edit), which no trigger
/// counts. From then on every move of the file's `PRAGMA data_version` moves
/// every group, whether or not a counted commit could explain it, and none
/// panics as an uncounted writer. A file no test declares keeps the panic.
///
/// The declaration is by path, as SQLite names the database it opens
/// ([`declared_path`]: every symbolic link resolved), not by file identity:
/// it lasts across reopens of that path and outlives every connection, and a
/// test's temporary directory gives its path to no other test, even one whose
/// database reuses the inode.
#[cfg(any(test, feature = "test-support"))]
pub fn expect_uncounted_writes_for_test(path: &Path) {
    lock(&UNCOUNTED_WRITERS).insert(declared_path(path));
}

/// `path` as SQLite names the database: every symbolic link resolved, the
/// file name's included. The file name's links are read with `read_link`,
/// which never opens the database (closing a descriptor of it would drop this
/// process's POSIX locks on it), and its directory is canonicalized.
#[cfg(any(test, feature = "test-support"))]
fn declared_path(path: &Path) -> PathBuf {
    /// SQLite's own limit on links followed in one name.
    const MAX_LINKS: usize = 100;
    let mut path = path.to_path_buf();
    for _ in 0..MAX_LINKS {
        let Ok(target) = std::fs::read_link(&path) else {
            break;
        };
        path = match path.parent() {
            Some(directory) => directory.join(target),
            None => target,
        };
    }
    match (path.parent(), path.file_name()) {
        (Some(directory), Some(name)) => std::fs::canonicalize(directory)
            .map(|directory| directory.join(name))
            .unwrap_or_else(|_| path.clone()),
        _ => path,
    }
}

#[cfg(any(test, feature = "test-support"))]
fn has_uncounted_writer(path: Option<&Path>) -> bool {
    path.is_some_and(|path| lock(&UNCOUNTED_WRITERS).contains(path))
}

/// What identifies a database file. On Unix, its device and inode, so every
/// path to one file (a hard link, a symlink, another spelling of the name)
/// shares one count. Elsewhere, its canonical path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum FileKey {
    #[cfg(unix)]
    Inode {
        device: u64,
        inode: u64,
    },
    Path(PathBuf),
}

impl FileKey {
    fn of(path: &Path) -> Self {
        // `metadata` stats the path; it opens no descriptor, so it cannot
        // drop this process's POSIX locks on the database.
        #[cfg(unix)]
        if let Ok(metadata) = std::fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            return Self::Inode {
                device: metadata.dev(),
                inode: metadata.ino(),
            };
        }
        Self::Path(std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
    }
}

#[derive(Default)]
struct Counts {
    /// The last value handed out; every applied note takes the next one.
    sequence: u64,
    /// Rows written through any connection to the file, as applied.
    writes: u64,
    /// Commits made through any of this process's counted connections to the
    /// file, as applied: what explains a move of another connection's
    /// `PRAGMA data_version`.
    commits: u64,
    /// Changes of the file that move other connections' `PRAGMA
    /// data_version` without a commit hook, made through any of this
    /// process's counted connections: WAL truncates and `VACUUM`s
    /// ([`HooklessMove`]), and rollbacks, which reset the WAL header too when
    /// the transaction had spilled pages into a WAL that was fully
    /// checkpointed. Each is applied when made, with its connection held.
    hookless: u64,
    /// Writes this counter could not attribute to one group: they move every
    /// group.
    unattributed: GroupWriteGeneration,
    groups: HashMap<Vec<u8>, GroupWriteGeneration>,
    /// The path the file was first opened by, under test (see
    /// [`expect_uncounted_writes_for_test`]).
    #[cfg(any(test, feature = "test-support"))]
    path: Option<PathBuf>,
    /// This process's counted connections to the file.
    connections: Vec<WeakSharedConnection>,
}

impl Counts {
    fn note(&mut self, group: Option<Vec<u8>>, scope: i64) {
        self.sequence += 1;
        let sequence = self.sequence;
        let entry = match group {
            Some(group) => self.groups.entry(group).or_default(),
            None => &mut self.unattributed,
        };
        entry.state = sequence;
        if scope == COMMITTED {
            entry.committed = sequence;
        }
    }
}

/// One connection's part of the counts.
#[derive(Default)]
struct ConnectionCounts {
    pending: Mutex<Pending>,
    /// Commits SQLite made on the connection (its commit hook) that have not
    /// joined the file's counts yet.
    commits: AtomicU64,
}

/// One connection's notes that have not joined the file's counts yet.
#[derive(Default)]
struct Pending {
    notes: Vec<(Option<Vec<u8>>, i64)>,
    /// The connection's `total_changes` when its writes last joined.
    applied_changes: u64,
    /// This connection's commits that have joined the file's count.
    own_commits: u64,
    /// This connection's part of [`Counts::hookless`].
    own_hookless: u64,
    /// The connection's last check.
    checked: Option<Checked>,
}

/// What one check of a connection's `PRAGMA data_version` saw.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Checked {
    data_version: i64,
    /// Commits other connections had applied then.
    commits: u64,
    /// [`Counts::hookless`] moves other connections had made then.
    hookless: u64,
}

/// The counts for one database file, shared by every handle this process
/// opens on it, plus the part of one connection. Entries are never removed:
/// a forgotten group keeps its last value, so a re-created one can never
/// present a value an earlier answer was cached under.
#[derive(Clone, Default)]
pub(crate) struct GroupWriteCounter {
    file: Arc<Mutex<Counts>>,
    connection: Arc<ConnectionCounts>,
}

impl GroupWriteCounter {
    fn for_file(file: Option<PathBuf>, connection: &SharedConnection) -> Self {
        let counter = match file {
            None => Self::default(),
            Some(file) => {
                let key = FileKey::of(&file);
                let mut files = FILES
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                files.retain(|_, counts| counts.strong_count() > 0);
                match files.get(&key).and_then(Weak::upgrade) {
                    Some(file) => Self {
                        file,
                        connection: Arc::default(),
                    },
                    None => {
                        let counter = Self::default();
                        #[cfg(any(test, feature = "test-support"))]
                        {
                            counter.lock().path = Some(declared_path(&file));
                        }
                        files.insert(key, Arc::downgrade(&counter.file));
                        counter
                    }
                }
            }
        };
        {
            let mut counts = counter.lock();
            counts.connections.retain(WeakSharedConnection::is_alive);
            counts.connections.push(connection.downgrade());
        }
        counter
    }

    pub(crate) fn generation(&self, group_id: &GroupId) -> GroupWriteGeneration {
        let counts = self.lock();
        let group = counts
            .groups
            .get(group_id.as_slice())
            .copied()
            .unwrap_or_default();
        GroupWriteGeneration {
            state: group.state.max(counts.unattributed.state),
            committed: group.committed.max(counts.unattributed.committed),
        }
    }

    /// Rows written to the file through any of this process's connections,
    /// counted as for [`Self::generation`], after checking through
    /// `connection` that nothing else wrote the file (see
    /// [`Self::check_unexplained_commits`]).
    pub(crate) fn writes(&self, connection: &SharedConnection) -> u64 {
        self.check_unexplained_commits(connection);
        self.lock().writes
    }

    /// The safety net under the triggers: SQLite moves a connection's
    /// `PRAGMA data_version` when any other connection, in this process or
    /// another, commits to the file. A move that no commit by another of this
    /// process's counted connections explains may have been made by a writer
    /// the triggers did not see, so every group's count and the write count
    /// move.
    ///
    /// SQLite also moves it without a commit hook: a WAL truncate (its own
    /// checkpoints, a close's), a `VACUUM`, and the rollback of a transaction
    /// that spilled into a fully checkpointed WAL. Every other path that
    /// moves it fires the commit hook, needs no other connection open (the
    /// last close, a journal-mode change), writes no file a counted
    /// connection has open (a SQLCipher rekey, a backup), or follows an I/O
    /// fault.
    /// When another counted connection made such a move since the last
    /// check, the move is not reported: nothing is logged and nothing panics.
    /// Every group still moves, so an uncounted commit in the same window
    /// costs a rebuild, never a stale answer. Without one, the move is
    /// reported, and under test it panics: every writer must be counted.
    ///
    /// The cost: under test, an uncounted commit is not flagged when another
    /// counted connection truncated the WAL, vacuumed or rolled back a
    /// transaction (read-only ones included) between two reads of this
    /// connection's count. For an idle connection that window can be long.
    ///
    /// The check holds every other counted connection to the file, so none is
    /// partway through a commit its release has not applied yet; when one is
    /// busy (a closing one included, until its close has taken it), or inside
    /// a transaction, it waits for a later read. A commit counts once SQLite
    /// calls the commit hook, even if the commit then fails: that can explain
    /// a move that did not happen, never flag one that did.
    fn check_unexplained_commits(&self, connection: &SharedConnection) {
        let Ok(own) = connection.lock() else {
            return;
        };
        if !own.is_autocommit() {
            // A's publish reads counts only at a quiescent point, outside any
            // transaction on its connection (mdk#3273).
            #[cfg(any(test, feature = "test-support"))]
            panic!("the group write count was read inside an open transaction");
            #[cfg(not(any(test, feature = "test-support")))]
            return;
        }
        let others: Vec<SharedConnection> = self
            .lock()
            .connections
            .iter()
            .filter_map(WeakSharedConnection::upgrade)
            .filter(|other| !other.same_as(connection))
            .collect();
        let mut held = Vec::with_capacity(others.len());
        for other in &others {
            match other.try_lock_idle() {
                Ok(Some(guard)) if guard.is_autocommit() => held.push(guard),
                Ok(_) => return,
                // Taken by its close, which waits out every guard on it: its
                // commits were all applied, and it makes no more.
                Err(_) => {}
            }
        }
        let Ok(data_version) = own.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
        else {
            return;
        };
        let reported = {
            let mut pending = lock(&self.connection.pending);
            let mut counts = self.lock();
            #[cfg(any(test, feature = "test-support"))]
            let declared = has_uncounted_writer(counts.path.as_deref());
            #[cfg(not(any(test, feature = "test-support")))]
            let declared = false;
            let now = Checked {
                data_version,
                commits: counts.commits.saturating_sub(pending.own_commits),
                hookless: counts.hookless.saturating_sub(pending.own_hookless),
            };
            let (unexplained, reported) = match pending.checked {
                Some(last) if last.data_version != data_version => {
                    // A declared writer's commit may land beside a counted
                    // one, which would explain the move: any move counts for
                    // such a file.
                    let unexplained = declared || last.commits == now.commits;
                    (
                        unexplained,
                        unexplained && !declared && last.hookless == now.hookless,
                    )
                }
                _ => (false, false),
            };
            if unexplained {
                counts.note(None, COMMITTED);
                counts.writes += 1;
            }
            pending.checked = Some(now);
            reported
        };
        drop(held);
        drop(own);
        if reported {
            tracing::warn!(
                target: "storage_sqlite::group_writes",
                method = "check_unexplained_commits",
                "the database changed through a writer this process does not count; every group's count moved"
            );
            #[cfg(any(test, feature = "test-support"))]
            panic!(
                "the database changed through a writer this process does not count: \
                 open it through `SqliteAccountStorage` so its writes are counted"
            );
        }
    }

    /// Fold this connection's pending notes, writes and commits into the
    /// file's counts, unless a transaction on it is still open.
    fn apply(&self, connection: &Connection) {
        if !connection.is_autocommit() {
            return;
        }
        let mut pending = lock(&self.connection.pending);
        let commits = self.connection.commits.swap(0, Ordering::AcqRel);
        let changes = connection.total_changes();
        if pending.notes.is_empty() && changes == pending.applied_changes && commits == 0 {
            return;
        }
        let mut counts = self.lock();
        counts.writes += changes.saturating_sub(pending.applied_changes);
        pending.applied_changes = changes;
        counts.commits += commits;
        pending.own_commits += commits;
        for (group, scope) in pending.notes.drain(..) {
            counts.note(group, scope);
        }
    }

    /// Apply a [`Counts::hookless`] move this connection is about to make,
    /// or made in a rollback, with the connection held: no check of another
    /// connection can run until it is released, so none sees the move
    /// before this. A `VACUUM` also moves every group, since it may renumber
    /// rows without a trigger seeing them.
    fn note_hookless_move(&self, vacuum: bool) {
        let mut pending = lock(&self.connection.pending);
        let mut counts = self.lock();
        counts.hookless += 1;
        pending.own_hookless += 1;
        if vacuum {
            counts.note(None, COMMITTED);
            counts.writes += 1;
        }
    }

    fn lock(&self) -> MutexGuard<'_, Counts> {
        lock(&self.file)
    }

    #[cfg(test)]
    fn shares_counts_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.file, &other.file)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn group_named(kind: i64, key: ValueRef<'_>) -> Option<Option<Vec<u8>>> {
    match (kind, key) {
        (EVERY_GROUP, _) => Some(None),
        (_, ValueRef::Null) => None,
        (RAW_ID, ValueRef::Blob(bytes)) => Some(Some(bytes.to_vec())),
        (HEX_ID, ValueRef::Text(text)) => Some(hex::decode(text).ok()),
        (OPENMLS_GROUP_KEY, ValueRef::Blob(bytes)) => Some(
            serde_json::from_slice::<openmls::group::GroupId>(bytes)
                .ok()
                .map(|group| group.as_slice().to_vec()),
        ),
        _ => Some(None),
    }
}

/// Register the counting function and commit hook on `connection`, create
/// the TEMP triggers that call it, and apply its notes as it is released. Run
/// once per connection, after migrations.
pub(crate) fn install(connection: &SharedConnection) -> StorageResult<GroupWriteCounter> {
    let counter = {
        let conn = connection.lock()?;
        let counter =
            GroupWriteCounter::for_file(crate::cross::handles::database_file(&conn)?, connection);
        lock(&counter.connection.pending).applied_changes = conn.total_changes();
        let noted = Arc::clone(&counter.connection);
        conn.create_scalar_function(FUNCTION, 3, FunctionFlags::SQLITE_UTF8, move |ctx| {
            if let Some(group) = group_named(ctx.get::<i64>(1)?, ctx.get_raw(2)) {
                lock(&noted.pending).notes.push((group, ctx.get::<i64>(0)?));
            }
            Ok(0i64)
        })
        .storage()?;
        conn.execute_batch(&trigger_sql()).storage()?;
        conn.execute_batch(&replace_trigger_sql(&conn)?).storage()?;
        // After the TEMP triggers, whose creation writes only this
        // connection's TEMP schema. A later TEMP write still counts as a
        // commit: it can explain a move it did not cause, never flag one.
        let committed = Arc::clone(&counter.connection);
        conn.commit_hook(Some(move || {
            committed.commits.fetch_add(1, Ordering::AcqRel);
            false
        }))
        .storage()?;
        // SQLite cannot say whether the transaction spilled, or whether it
        // wrote at all, so every rollback counts.
        let rolled_back = counter.clone();
        conn.rollback_hook(Some(move || rolled_back.note_hookless_move(false)))
            .storage()?;
        counter
    };
    let applied = counter.clone();
    let moved = counter.clone();
    connection.set_hooks(ConnectionHooks {
        release: Box::new(move |conn| applied.apply(conn)),
        hookless_move: Box::new(move |change| {
            moved.note_hookless_move(change == HooklessMove::Vacuum);
        }),
    })?;
    Ok(counter)
}

/// How a covered table names the group a row belongs to.
struct Covered {
    table: &'static str,
    column: &'static str,
    kind: i64,
    scope: i64,
    /// Rows that matter, as a condition on `{row}`; empty for every row.
    rows: fn(&str) -> String,
}

fn every_row(_: &str) -> String {
    String::new()
}

fn ratchet_list() -> String {
    format!(
        "({})",
        ratchet_labels()
            .iter()
            .map(|label| format!("X'{}'", hex::encode(label)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Commit-derived OpenMLS state, without the per-message ratchet.
fn openmls_rows(row: &str) -> String {
    format!(
        "{row}.group_key IS NOT NULL AND {row}.label NOT IN {}",
        ratchet_list()
    )
}

/// A commit's message row matters only while convergence has withdrawn it:
/// undelivered-commit status skips withdrawn commits.
fn withdrawn_messages(row: &str) -> String {
    format!(
        "{row}.state IN ({}, {})",
        message_state_to_i64(MessageState::EpochInvalidated),
        message_state_to_i64(MessageState::ConvergenceDeferred),
    )
}

/// Every table a published group answer reads.
fn covered_tables() -> Vec<Covered> {
    WHOLE_ROW_TABLES
        .iter()
        .map(|&(table, column, kind, scope)| Covered {
            table,
            column,
            kind,
            scope,
            rows: every_row,
        })
        .chain([
            Covered {
                table: "openmls_values",
                column: "group_key",
                kind: OPENMLS_GROUP_KEY,
                scope: COMMITTED,
                rows: openmls_rows,
            },
            Covered {
                table: "cgka_messages",
                column: "group_id",
                kind: RAW_ID,
                scope: STATE,
                rows: withdrawn_messages,
            },
            Covered {
                table: "account_groups",
                column: "group_id_hex",
                kind: HEX_ID,
                scope: STATE,
                rows: every_row,
            },
        ])
        .collect()
}

/// A unique key of a covered table that does not include its group column,
/// as `(column, collation)` pairs; a `None` column is an expression.
type UniqueKey = Vec<(Option<String>, String)>;

/// Every unique key of `table` that leaves out `group_column`: the rowid
/// alias, the primary key and each unique index.
fn keys_without_group(
    conn: &Connection,
    table: &str,
    group_column: &str,
) -> StorageResult<Vec<UniqueKey>> {
    let mut keys = Vec::new();
    let primary: Vec<(String, String)> = conn
        .prepare(&format!(
            "SELECT name, type FROM pragma_table_info('{table}') WHERE pk > 0 ORDER BY pk"
        ))
        .storage()?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?;
    // An INTEGER PRIMARY KEY is the rowid, which has no index of its own.
    if let [(column, kind)] = primary.as_slice()
        && kind.eq_ignore_ascii_case("INTEGER")
        && column != group_column
    {
        keys.push(vec![(Some(column.clone()), "BINARY".to_owned())]);
    }
    let indexes: Vec<String> = conn
        .prepare(&format!(
            "SELECT name FROM pragma_index_list('{table}') WHERE \"unique\" = 1"
        ))
        .storage()?
        .query_map([], |row| row.get(0))
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?;
    for index in indexes {
        let key: UniqueKey = conn
            .prepare(&format!(
                "SELECT name, coll FROM pragma_index_xinfo('{index}') WHERE key = 1 ORDER BY seqno"
            ))
            .storage()?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .storage()?
            .collect::<Result<_, _>>()
            .storage()?;
        if !key
            .iter()
            .any(|(column, _)| column.as_deref() == Some(group_column))
        {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Triggers that count the row a REPLACE would delete. SQLite fires no delete
/// trigger for a row it deletes to resolve a REPLACE conflict (recursive
/// triggers are off), so when a unique key leaves out the group column, the
/// row it deletes may belong to another group than the row written. Before
/// the write, each trigger notes the group of any row that holds the new key.
/// A key with an expression column moves every group on every write.
fn replace_trigger_sql(conn: &Connection) -> StorageResult<String> {
    let mut sql = String::new();
    for covered in covered_tables() {
        let table = covered.table;
        for (index, key) in keys_without_group(conn, table, covered.column)?
            .into_iter()
            .enumerate()
        {
            let name = format!("mdk_group_writes_{table}_replace_{index}");
            let columns: Option<Vec<(String, String)>> = key
                .into_iter()
                .map(|(column, collation)| column.map(|column| (column, collation)))
                .collect();
            let Some(columns) = columns else {
                let every = format!("{FUNCTION}({}, {EVERY_GROUP}, NULL)", covered.scope);
                sql.push_str(&format!(
                    "CREATE TEMP TRIGGER {name}_insert BEFORE INSERT ON main.{table} BEGIN SELECT {every}; END;\n\
                     CREATE TEMP TRIGGER {name}_update BEFORE UPDATE ON main.{table} BEGIN SELECT {every}; END;\n"
                ));
                continue;
            };
            let mut matches: Vec<String> = columns
                .iter()
                .map(|(column, collation)| {
                    format!("existing.{column} = NEW.{column} COLLATE {collation}")
                })
                .collect();
            let rows = (covered.rows)("existing");
            if !rows.is_empty() {
                matches.push(format!("({rows})"));
            }
            let lookup = format!(
                "SELECT {FUNCTION}({}, {}, existing.{}) FROM main.{table} AS existing WHERE {};",
                covered.scope,
                covered.kind,
                covered.column,
                matches.join(" AND ")
            );
            let moved = columns
                .iter()
                .map(|(column, _)| format!("NEW.{column} IS NOT OLD.{column}"))
                .collect::<Vec<_>>()
                .join(" OR ");
            sql.push_str(&format!(
                "CREATE TEMP TRIGGER {name}_insert BEFORE INSERT ON main.{table} BEGIN {lookup} END;\n\
                 CREATE TEMP TRIGGER {name}_update BEFORE UPDATE ON main.{table} WHEN {moved} BEGIN {lookup} END;\n"
            ));
        }
    }
    Ok(sql)
}

/// Every table a published group answer reads, with the column that names
/// the group and the scope a write moves.
const WHOLE_ROW_TABLES: &[(&str, &str, i64, i64)] = &[
    ("cgka_groups", "id", RAW_ID, COMMITTED),
    ("cgka_convergence_passes", "group_id", RAW_ID, STATE),
    ("cgka_disband_requests", "group_id", RAW_ID, STATE),
    ("cgka_disband_candidates", "group_id", RAW_ID, STATE),
    ("cgka_disband_tombstones", "group_id", RAW_ID, STATE),
    ("cgka_outbound_fanout", "group_id", RAW_ID, STATE),
    ("cgka_group_maintenance", "group_id", RAW_ID, STATE),
    ("cgka_maintenance_obligations", "group_id", RAW_ID, STATE),
    ("cgka_group_evolutions", "group_id", RAW_ID, STATE),
    ("cgka_transport_fanout", "group_id", RAW_ID, STATE),
    ("device_groups", "group_id_hex", HEX_ID, STATE),
];

fn trigger_sql() -> String {
    let mut sql = String::new();
    let mut trigger = |name: &str, event: &str, table: &str, when: &str, calls: &[String]| {
        let when = if when.is_empty() {
            String::new()
        } else {
            format!(" WHEN {when}")
        };
        let body: String = calls
            .iter()
            .map(|call| format!(" SELECT {call};"))
            .collect();
        sql.push_str(&format!(
            "CREATE TEMP TRIGGER mdk_group_writes_{name} AFTER {event} ON main.{table}{when} BEGIN{body} END;\n"
        ));
    };
    let call =
        |scope: i64, kind: i64, column: &str| format!("{FUNCTION}({scope}, {kind}, {column})");

    for (table, column, kind, scope) in WHOLE_ROW_TABLES {
        let new = call(*scope, *kind, &format!("NEW.{column}"));
        let old = call(*scope, *kind, &format!("OLD.{column}"));
        trigger(
            &format!("{table}_insert"),
            "INSERT",
            table,
            "",
            std::slice::from_ref(&new),
        );
        trigger(
            &format!("{table}_update"),
            "UPDATE",
            table,
            "",
            &[old.clone(), new],
        );
        trigger(&format!("{table}_delete"), "DELETE", table, "", &[old]);
    }

    // Commit-derived OpenMLS state, without the per-message ratchet.
    let mls = |row: &str| {
        (
            openmls_rows(row),
            call(COMMITTED, OPENMLS_GROUP_KEY, &format!("{row}.group_key")),
        )
    };
    let (new_when, new) = mls("NEW");
    let (old_when, old) = mls("OLD");
    trigger(
        "openmls_insert",
        "INSERT",
        "openmls_values",
        &new_when,
        std::slice::from_ref(&new),
    );
    trigger(
        "openmls_update",
        "UPDATE",
        "openmls_values",
        &format!("({old_when}) OR ({new_when})"),
        &[old.clone(), new],
    );
    trigger(
        "openmls_delete",
        "DELETE",
        "openmls_values",
        &old_when,
        &[old],
    );

    // A commit's message row matters only while convergence has withdrawn it.
    let new = call(STATE, RAW_ID, "NEW.group_id");
    let old = call(STATE, RAW_ID, "OLD.group_id");
    trigger(
        "messages_insert",
        "INSERT",
        "cgka_messages",
        &withdrawn_messages("NEW"),
        std::slice::from_ref(&new),
    );
    trigger(
        "messages_update",
        "UPDATE",
        "cgka_messages",
        &format!(
            "{} OR {}",
            withdrawn_messages("OLD"),
            withdrawn_messages("NEW")
        ),
        &[old.clone(), new],
    );
    trigger(
        "messages_delete",
        "DELETE",
        "cgka_messages",
        &withdrawn_messages("OLD"),
        &[old],
    );

    // The roster read overlays the stored self membership; the rest of the
    // row is the in-memory mirror's.
    let new = call(STATE, HEX_ID, "NEW.group_id_hex");
    let old = call(STATE, HEX_ID, "OLD.group_id_hex");
    trigger(
        "account_groups_insert",
        "INSERT",
        "account_groups",
        "",
        std::slice::from_ref(&new),
    );
    trigger(
        "account_groups_update",
        "UPDATE",
        "account_groups",
        "OLD.self_membership IS NOT NEW.self_membership \
         OR OLD.group_id_hex IS NOT NEW.group_id_hex",
        &[old.clone(), new],
    );
    trigger(
        "account_groups_delete",
        "DELETE",
        "account_groups",
        "",
        &[old],
    );
    sql
}

#[cfg(test)]
mod tests {
    use super::expect_uncounted_writes_for_test;
    use crate::SqliteAccountStorage;
    use crate::protocol::openmls_storage::{mls_group_key, ratchet_labels};
    use cgka_traits::storage::{GroupWriteGeneration, StorageProvider};
    use cgka_traits::types::GroupId;

    fn generation(storage: &SqliteAccountStorage, group: &GroupId) -> GroupWriteGeneration {
        storage.group_write_generation(group).unwrap()
    }

    fn write_openmls(storage: &SqliteAccountStorage, group: &GroupId, label: &[u8], key: &str) {
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO openmls_values (provider_version, label, storage_key, group_key, value)
                 VALUES (1, ?1, ?2, ?3, X'00')",
                rusqlite::params![label, key.as_bytes(), mls_group_key(group).unwrap()],
            )
            .unwrap();
    }

    /// Commit-derived OpenMLS state moves both scopes of the group its key
    /// names and of no other group. The application-message ratchet moves
    /// neither, so ingesting a message leaves the group's answers cached.
    #[test]
    fn openmls_rows_move_their_group_unless_they_are_the_message_ratchet() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![1; 16]);
        let other = GroupId::new(vec![2; 16]);
        let before = generation(&storage, &group);

        write_openmls(&storage, &group, b"tree", "tree");
        let committed = generation(&storage, &group);
        assert!(committed.state > before.state);
        assert!(committed.committed > before.committed);
        assert_eq!(
            generation(&storage, &other),
            GroupWriteGeneration::default()
        );

        for (index, label) in ratchet_labels().into_iter().enumerate() {
            write_openmls(&storage, &group, label, &format!("ratchet-{index}"));
        }
        assert_eq!(generation(&storage, &group), committed);
    }

    fn write_device_group(storage: &SqliteAccountStorage, group: &GroupId) {
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
                 VALUES (?1, 'untrusted', NULL, 0)",
                [hex::encode(group.as_slice())],
            )
            .unwrap();
    }

    /// The app's rows for a group move its state scope, not its committed one.
    #[test]
    fn a_device_group_row_moves_only_the_state_scope() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![3; 16]);
        let before = generation(&storage, &group);

        write_device_group(&storage, &group);
        let after = generation(&storage, &group);
        assert!(after.state > before.state);
        assert_eq!(after.committed, before.committed);
    }

    /// Every connection this process opens on a database file counts into
    /// one generation, and a write moves it only once committed: until then
    /// another connection reads the state before the write, under the count
    /// from before it.
    #[test]
    fn a_write_moves_the_files_count_once_another_connection_can_read_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-writes.sqlite");
        let open = || {
            SqliteAccountStorage::from_connection_with_options(
                rusqlite::Connection::open(&path).unwrap(),
                crate::SqliteStorageOptions::default(),
            )
            .unwrap()
        };
        let engine = open();
        let app = open();
        assert!(!engine.shares_connection_with(&app));
        let group = GroupId::new(vec![4; 16]);
        let before = generation(&engine, &group);
        let writes = engine.write_count();

        app.lock().unwrap().execute_batch("BEGIN").unwrap();
        write_device_group(&app, &group);
        assert_eq!(generation(&engine, &group), before);
        assert_eq!(engine.write_count(), writes);

        app.lock().unwrap().execute_batch("COMMIT").unwrap();
        assert!(generation(&engine, &group).state > before.state);
        assert!(engine.write_count() > writes);
    }

    fn open_file(path: &std::path::Path) -> SqliteAccountStorage {
        SqliteAccountStorage::from_connection_with_options(
            rusqlite::Connection::open(path).unwrap(),
            crate::SqliteStorageOptions::default(),
        )
        .unwrap()
    }

    fn execute(storage: &SqliteAccountStorage, sql: &str) {
        storage.lock().unwrap().execute_batch(sql).unwrap();
    }

    /// Two paths to one database file are one file: their handles share one
    /// count, or a write through one would leave the other's answers cached.
    #[cfg(unix)]
    #[test]
    fn every_path_to_a_database_file_shares_one_count() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let path = real.join("group-writes.sqlite");
        let first = open_file(&path);
        // Move everything into the main file: a hard link has its own WAL.
        execute(&first, "PRAGMA wal_checkpoint(TRUNCATE);");
        let hard_link = directory.path().join("hard-link.sqlite");
        std::fs::hard_link(&path, &hard_link).unwrap();
        let symlinked = directory.path().join("symlinked");
        std::os::unix::fs::symlink(&real, &symlinked).unwrap();

        for other in [hard_link, symlinked.join("group-writes.sqlite")] {
            let second = open_file(&other);
            assert!(!first.shares_connection_with(&second));
            assert!(
                first.group_writes.shares_counts_with(&second.group_writes),
                "{other:?}"
            );
        }
    }

    /// The schema gate. A write a trigger does not see would leave a group's
    /// answers cached, so every way SQLite writes a covered table must be
    /// counted:
    /// - each covered table has its own insert, update and delete triggers;
    /// - only covered tables write covered tables, through a foreign-key
    ///   action or a persistent trigger, so every cascade and trigger write
    ///   starts at a counted write too;
    /// - every foreign-key action into a covered table is keyed by the group
    ///   on both sides, so a cascade moves the group its parent's write does;
    /// - every unique key that leaves out the group column has its
    ///   REPLACE-conflict triggers, and none is an expression.
    #[test]
    fn every_write_into_a_covered_table_is_counted() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let conn = storage.lock().unwrap();
        let strings = |sql: &str| -> Vec<Vec<String>> {
            let mut statement = conn.prepare(sql).unwrap();
            let width = statement.column_count();
            statement
                .query_map([], |row| {
                    (0..width)
                        .map(|index| Ok(row.get::<_, Option<String>>(index)?.unwrap_or_default()))
                        .collect()
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let covered = super::covered_tables();
        let group_column = |table: &str| {
            covered
                .iter()
                .find(|covered| covered.table == table)
                .map(|covered| covered.column)
        };

        let counting = strings(
            "SELECT tbl_name, sql FROM sqlite_temp_master
             WHERE type = 'trigger' AND name LIKE 'mdk_group_writes_%'",
        );
        for covered in &covered {
            for event in ["INSERT", "UPDATE", "DELETE"] {
                assert!(
                    counting.iter().any(|row| row[0] == covered.table
                        && row[1].contains(&format!("AFTER {event} ON main.{}", covered.table))),
                    "{} has no {event} trigger",
                    covered.table
                );
            }
        }

        // Which tables write which: foreign-key actions and persistent
        // trigger bodies.
        let mut writers: Vec<(String, String)> = Vec::new();
        for table in strings("SELECT name FROM sqlite_master WHERE type = 'table'") {
            let table = &table[0];
            for fk in strings(&format!(
                "SELECT \"table\", \"from\", \"to\", on_update, on_delete
                 FROM pragma_foreign_key_list('{table}')"
            )) {
                let acts = |action: &str| !matches!(action, "NO ACTION" | "RESTRICT");
                if !(acts(&fk[3]) || acts(&fk[4])) {
                    continue;
                }
                writers.push((fk[0].clone(), table.clone()));
                if let Some(child_group) = group_column(table) {
                    let parent_group = group_column(&fk[0])
                        .unwrap_or_else(|| panic!("{table} cascades from uncovered {}", fk[0]));
                    let to = if fk[2].is_empty() {
                        strings(&format!(
                            "SELECT name FROM pragma_table_info('{}') WHERE pk = 1",
                            fk[0]
                        ))[0][0]
                            .clone()
                    } else {
                        fk[2].clone()
                    };
                    assert_eq!(
                        (fk[1].as_str(), to.as_str()),
                        (child_group, parent_group),
                        "{table}'s cascade from {} is not keyed by the group",
                        fk[0]
                    );
                }
            }
        }
        for trigger in strings("SELECT tbl_name, sql FROM sqlite_master WHERE type = 'trigger'") {
            let sql = trigger[1].to_ascii_lowercase().replace("main.", "");
            let words: Vec<&str> = sql
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|word| !word.is_empty())
                .skip_while(|word| *word != "begin")
                .collect();
            assert!(!words.is_empty(), "{} has no body", trigger[0]);
            for (index, word) in words.iter().enumerate() {
                let target = match *word {
                    "into" => words.get(index + 1),
                    "delete" => words.get(index + 2),
                    "update" => match words.get(index + 1) {
                        Some(&"or") => words.get(index + 3),
                        Some(&"set") => None,
                        other => other,
                    },
                    _ => None,
                };
                if let Some(target) = target {
                    writers.push((trigger[0].clone(), (*target).to_owned()));
                }
            }
        }
        for (writer, written) in &writers {
            if group_column(written).is_some() {
                assert!(
                    group_column(writer).is_some(),
                    "{writer} writes covered {written} but is not covered"
                );
            }
        }

        for covered in &covered {
            let keys = super::keys_without_group(&conn, covered.table, covered.column).unwrap();
            assert!(
                keys.iter()
                    .all(|key| key.iter().all(|(column, _)| column.is_some())),
                "{} has a unique expression key",
                covered.table
            );
            for index in 0..keys.len() {
                for event in ["insert", "update"] {
                    let name =
                        format!("mdk_group_writes_{}_replace_{index}_{event}", covered.table);
                    assert_eq!(
                        strings(&format!(
                            "SELECT name FROM sqlite_temp_master WHERE name = '{name}'"
                        ))
                        .len(),
                        1,
                        "{name}"
                    );
                }
            }
        }
    }

    /// A REPLACE deletes the row that held its key without a delete
    /// trigger. When the key leaves out the group, that row's group moves too.
    #[test]
    fn a_replace_moves_the_group_of_the_row_it_deletes() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let replaced = GroupId::new(vec![5; 16]);
        let writer = GroupId::new(vec![6; 16]);
        write_openmls(&storage, &replaced, b"tree", "shared-key");
        let before = generation(&storage, &replaced);

        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO openmls_values
                     (provider_version, label, storage_key, group_key, value)
                 VALUES (1, ?1, ?2, ?3, X'01')",
                rusqlite::params![
                    b"tree".as_slice(),
                    "shared-key".as_bytes(),
                    mls_group_key(&writer).unwrap()
                ],
            )
            .unwrap();
        let after = generation(&storage, &replaced);
        assert!(after.committed > before.committed);
    }

    fn insert_group(storage: &SqliteAccountStorage, group: &GroupId) {
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, x'00')",
                [group.as_slice()],
            )
            .unwrap();
    }

    /// A cascade and an unkeyed delete count every row they delete, each for
    /// its own group: SQLite runs row triggers for both.
    #[test]
    fn cascades_and_unkeyed_deletes_count_every_row() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![7; 16]);
        let marker = GroupId::new(vec![8; 16]);
        insert_group(&storage, &group);
        for commit in 1u8..=3 {
            storage
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO cgka_disband_candidates (group_id, commit_id, record)
                     VALUES (?1, ?2, x'00')",
                    rusqlite::params![group.as_slice(), [commit].as_slice()],
                )
                .unwrap();
        }
        // The marker's count is the last value handed out.
        write_device_group(&storage, &marker);
        let last = generation(&storage, &marker).state;

        storage
            .lock()
            .unwrap()
            .execute("DELETE FROM cgka_groups WHERE id = ?1", [group.as_slice()])
            .unwrap();
        // The group row and its three cascaded candidates.
        assert_eq!(generation(&storage, &group).state, last + 4);

        let others = [GroupId::new(vec![9; 16]), GroupId::new(vec![10; 16])];
        for other in &others {
            write_device_group(&storage, other);
        }
        let before: Vec<_> = others
            .iter()
            .map(|other| generation(&storage, other))
            .collect();
        execute(&storage, "DELETE FROM device_groups");
        for (other, before) in others.iter().zip(before) {
            assert!(generation(&storage, other).state > before.state);
        }
    }

    /// The safety net: a commit no counted connection made moves every
    /// group, and under test it panics. Commits through counted connections
    /// and another counted open explain themselves.
    #[test]
    fn only_an_uncounted_commit_trips_the_data_version_net() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-writes.sqlite");
        let engine = open_file(&path);
        let app = open_file(&path);
        let group = GroupId::new(vec![11; 16]);
        engine.write_count();

        write_device_group(&app, &group);
        execute(&app, "BEGIN; DELETE FROM device_groups; COMMIT;");
        let reopened = open_file(&path);
        engine.write_count();
        drop(reopened);

        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch(
            "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES ('ff', 'untrusted', NULL, 0)",
        )
        .unwrap();
        let before = (
            generation(&engine, &group),
            engine.group_writes.lock().writes,
        );
        let tripped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.write_count();
        }));
        assert!(tripped.is_err());
        assert!(generation(&engine, &group).committed > before.0.committed);
        assert!(engine.group_writes.lock().writes > before.1);
    }

    /// SQLite moves another connection's `PRAGMA data_version` without a
    /// commit hook for a WAL truncate (a maintenance pass's, a close's), a
    /// `VACUUM`, and a rollback, in a write or at a drop, whose spill reset a
    /// fully checkpointed WAL. Made through a counted connection, none is an
    /// uncounted writer: the other connection's next count read does not
    /// panic, and every group still moves, as a rebuild costs nothing stale.
    /// A truncate run around the helper is reported.
    #[test]
    fn a_counted_connections_move_without_a_commit_is_not_reported() {
        const SPILL: &str = "INSERT INTO spill SELECT randomblob(4000)
             FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100)
                   SELECT i FROM n)";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-writes.sqlite");
        let engine = open_file(&path);
        let app = open_file(&path);
        let group = GroupId::new(vec![15; 16]);
        execute(
            &app,
            "CREATE TABLE spill (bytes BLOB); PRAGMA cache_size = 10;",
        );
        let moves_every_group = |change: &str, make: &dyn Fn()| {
            engine.write_count();
            let before = generation(&engine, &group);
            make();
            let read = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.write_count();
            }));
            assert!(read.is_ok(), "{change} was reported");
            assert!(
                generation(&engine, &group).committed > before.committed,
                "{change} moved no group"
            );
        };

        moves_every_group("a truncate", &|| {
            assert!(app.app_storage().truncate_wal().unwrap());
        });
        moves_every_group("a vacuum", &|| {
            app.app_storage().make_non_incremental_for_test().unwrap();
        });
        // A spill starts the WAL over when every frame in it is checkpointed.
        const CHECKPOINTED: &str = "INSERT INTO spill VALUES (x'00'); PRAGMA wal_checkpoint;";
        execute(&app, CHECKPOINTED);
        moves_every_group("a rollback", &|| {
            execute(&app, &format!("BEGIN; {SPILL}; ROLLBACK;"));
        });
        // Opened first: an open's own commits would explain the move.
        let dropped = open_file(&path);
        execute(&dropped, &format!("PRAGMA cache_size = 10; {CHECKPOINTED}"));
        let dropped = std::cell::Cell::new(Some(dropped));
        moves_every_group("a drop", &|| {
            let dropped = dropped.take().unwrap();
            execute(&dropped, &format!("BEGIN; {SPILL};"));
        });

        engine.write_count();
        execute(&app, "PRAGMA wal_checkpoint(TRUNCATE)");
        let around = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.write_count();
        }));
        assert!(around.is_err());

        moves_every_group("a close", &|| app.close().unwrap());
    }

    /// A guard taken before a close began can still commit through the
    /// closing connection. The count check waits for that guard's release,
    /// which applies the commit, rather than skipping the closing connection
    /// and taking its commit for an uncounted writer's.
    #[test]
    fn a_commit_through_a_closing_connection_is_waited_out() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-writes.sqlite");
        let engine = open_file(&path);
        let app = open_file(&path);
        let untouched = GroupId::new(vec![14; 16]);
        engine.write_count();
        let before = generation(&engine, &untouched);

        let guard = app.lock().unwrap();
        app.connection.begin_close();
        guard
            .execute(
                "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
                 VALUES ('ff', 'untrusted', NULL, 0)",
                [],
            )
            .unwrap();
        engine.write_count();
        drop(guard);
        engine.write_count();
        assert_eq!(generation(&engine, &untouched).committed, before.committed);
        app.close().unwrap();
    }

    /// A test that declares its own writer gets the production answer (every
    /// group moves) and no panic, even when a counted commit lands in the
    /// same window and would explain the move.
    #[test]
    fn a_declared_writer_moves_every_group_beside_a_counted_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("group-writes.sqlite");
        let engine = open_file(&path);
        let app = open_file(&path);
        let group = GroupId::new(vec![12; 16]);
        engine.write_count();
        expect_uncounted_writes_for_test(&path);

        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch(
            "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES ('ff', 'untrusted', NULL, 0)",
        )
        .unwrap();
        write_device_group(&app, &GroupId::new(vec![13; 16]));
        let before = generation(&engine, &group);
        engine.write_count();
        assert!(generation(&engine, &group).committed > before.committed);
    }

    /// SQLite names a database by its path with every symbolic link resolved,
    /// the file name's included, so a declaration made by a symlinked file
    /// name covers the file it links to.
    #[cfg(unix)]
    #[test]
    fn a_declaration_by_a_symlinked_file_name_covers_its_file() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("group-writes.sqlite");
        let link = directory.path().join("linked.sqlite");
        std::os::unix::fs::symlink("group-writes.sqlite", &link).unwrap();
        let engine = open_file(&link);
        let group = GroupId::new(vec![14; 16]);
        engine.write_count();
        expect_uncounted_writes_for_test(&link);

        let raw = rusqlite::Connection::open(&real).unwrap();
        raw.execute_batch(
            "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES ('ff', 'untrusted', NULL, 0)",
        )
        .unwrap();
        let before = generation(&engine, &group);
        engine.write_count();
        assert!(generation(&engine, &group).committed > before.committed);
    }
}
