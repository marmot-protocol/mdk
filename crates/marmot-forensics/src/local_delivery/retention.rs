//! Retire a known closed inode before expiry, without weakening generic loss detection.

use super::*;

/// What an account's delivery cursor shows for one closed source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceDelivery {
    /// The cursor accepted every byte of this exact file, or it is empty.
    Delivered,
    /// The cursor still owes part of this file, or has not adopted it yet.
    Undelivered,
    /// No cursor will deliver this file: the account has none, the file
    /// belongs to another source, or a cursor overflow already recorded its
    /// loss.
    Untracked,
}

/// A read-only snapshot of one account's delivery cursor. It classifies
/// closed sources from their metadata, without opening them.
pub struct DeliveryCursorView {
    state: Option<State>,
}

impl DeliveryCursorView {
    /// Load the cursor in `state_dir`, if the account has one.
    pub fn load(state_dir: &Path) -> io::Result<Self> {
        let state = match read_cursor(state_dir)? {
            None => None,
            Some(bytes) => {
                let mut state = decode_state(&bytes, "version-1.jsonl")?;
                // A version 1 cursor did not record its source; its journals'
                // names show it. One that tracks nothing cannot say which
                // files it owes, so the budget leaves the account alone.
                if cursor_version(&bytes)? == 1 {
                    let journal = state
                        .journals
                        .first()
                        .ok_or_else(|| invalid("version 1 delivery cursor names no source"))?;
                    state.source = source_family(Path::new(&journal.segment))?.0;
                }
                check_header(&state)?;
                validate_state(&state, &state.source)?;
                Some(state)
            }
        };
        Ok(Self { state })
    }

    pub fn source_delivery(&self, path: &Path) -> io::Result<SourceDelivery> {
        let Some(state) = &self.state else {
            return Ok(SourceDelivery::Untracked);
        };
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(invalid("source is not a regular file"));
        }
        let (active_name, index) = source_family(path)?;
        if state.source != active_name {
            return Ok(SourceDelivery::Untracked);
        }
        let identity = match metadata_identity(&metadata) {
            Some(identity) => identity,
            None => source_identity(path)?,
        };
        let change_time = change_time_ns(&metadata);
        let matched = find_journal(state, identity);
        if let Some(journal) = matched.map(|index| &state.journals[index]) {
            // Without opening the file, only its name and change time
            // show the row still describes it rather than a reused inode.
            let name = path.file_name().and_then(|n| n.to_str());
            if name != Some(journal.segment.as_str())
                || journal.change_time == 0
                || journal.change_time != change_time
            {
                return Ok(SourceDelivery::Undelivered);
            }
        }
        Ok(classify(state, matched, index, metadata.len(), change_time))
    }
}

/// Age expiry. The caller excludes every writer of this file and fences this
/// directory's delivery work. Source bytes never change. The only
/// irreversible operation (unlink) runs after the closed alias, its final
/// observed length and any `ExpiredUndelivered` gap for its unaccepted extent
/// are durable.
pub fn expire_closed_source(path: &Path, state_dir: &Path) -> io::Result<bool> {
    expire_with(
        path,
        state_dir,
        Expiry::Age,
        |target| fs::remove_file(target),
        |delivery| delivery.publish(),
    )
}

/// Size-budget eviction, under the same exclusion as [`expire_closed_source`].
/// Removes the file only when the cursor shows nothing left to deliver from
/// it ([`SourceDelivery::Delivered`] or [`SourceDelivery::Untracked`]);
/// otherwise returns `Ok(false)` and leaves file and cursor untouched.
pub fn evict_delivered_source(path: &Path, state_dir: &Path) -> io::Result<bool> {
    expire_with(
        path,
        state_dir,
        Expiry::Budget,
        |target| fs::remove_file(target),
        |delivery| delivery.publish(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Expiry {
    /// Remove whatever is left, recording undelivered data as a gap.
    Age,
    /// Remove only what the cursor no longer owes.
    Budget,
}

pub(super) fn expire_with(
    path: &Path,
    state_dir: &Path,
    expiry: Expiry,
    unlink: impl FnOnce(&Path) -> io::Result<()>,
    publish: impl FnOnce(&mut LocalAuditDelivery) -> io::Result<()>,
) -> io::Result<bool> {
    let state_path = state_dir.join("local-delivery.json");
    let Some(bytes) = read_cursor(state_dir)? else {
        return remove_without_cursor(path, unlink);
    };
    let mut source = open_source(path)?;
    let identity = file_identity(&source)?;
    let metadata = source.metadata()?;
    let (len, change_time) = (metadata.len(), change_time_ns(&metadata));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid source name"))?;
    let (active_name, segment_index) = source_family(path)?;
    let stem = active_name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid source name"))?
        .to_owned();
    // One directory can retain files from a previous device identity. Its
    // current cursor has no authority over a different source family.
    let Some(mut state) = decode_for_family(&bytes, &active_name)? else {
        return remove_without_cursor(path, unlink);
    };
    drop_retired(&mut state);
    let mut matched = find_journal(&state, identity);
    // The cursor as published, if retiring a replaced generation changed it.
    let mut before_retirement = None;
    if let Some(index) = matched {
        let journal = &state.journals[index];
        // Never bless bytes as ACKed without a stored head to compare
        // against; such a source keeps the generic missing-source handling.
        if journal.fingerprint.is_empty() {
            return match expiry {
                Expiry::Age => remove_without_cursor(path, unlink),
                Expiry::Budget => Ok(false),
            };
        }
        // A reused inode or an externally changed source holds other bytes.
        // As discovery does, retire the old generation with its own loss
        // evidence and treat these bytes as an unadopted source.
        if len < journal.observed_len
            || len < journal.fingerprint_len as u64
            || !fingerprint_matches(
                &journal.fingerprint,
                &fingerprint(&mut source, journal.fingerprint_len as usize)?,
            )
        {
            if expiry == Expiry::Budget {
                return Ok(false);
            }
            let was_active = journal.segment == active_name;
            before_retirement = Some(state.clone());
            retire_missing(&mut state, index, was_active);
            matched = None;
        } else if expiry == Expiry::Budget
            && (journal.change_time == 0 || journal.change_time != change_time)
        {
            // The head covers only the first bytes. As the metadata view
            // does, evict only a file whose inode has not changed since the
            // cursor last saw it.
            return Ok(false);
        }
    }
    let status = classify(&state, matched, segment_index, len, change_time);
    if let Some(original) = before_retirement.clone()
        && (status == SourceDelivery::Untracked
            || (status == SourceDelivery::Delivered && len == 0))
    {
        // Nothing of these bytes needs adopting, but the retired
        // generation's loss evidence must be durable before the unlink.
        let mut delivery = LocalAuditDelivery {
            active: path.with_file_name(&active_name),
            state_path,
            state,
            fenced: false,
            state_limit: MAX_STATE_BYTES,
        };
        match fs::remove_file(delivery.state_path.with_extension("json.tmp")) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let result = publish(&mut delivery).and_then(|()| remove_without_cursor(path, unlink));
        if result.is_err() {
            delivery.state = original;
            let _ = fs::remove_file(delivery.state_path.with_extension("json.tmp"));
            let _ = delivery.publish_inner();
        }
        return result;
    }
    if status == SourceDelivery::Untracked {
        return remove_without_cursor(path, unlink);
    }
    let delivered = status == SourceDelivery::Delivered;
    if !delivered && expiry == Expiry::Budget {
        return Ok(false);
    }
    // An unchanged delivered sealed alias already has a durable final-length
    // proof, and an empty unadopted file holds nothing. Ordinary expiry needs
    // no cursor rewrite or extra staging space.
    let unchanged_alias = matched.is_some_and(|index| {
        name != active_name
            && state.journals[index].segment == name
            && state.journals[index].observed_len == len
    });
    if delivered && (unchanged_alias || matched.is_none()) {
        return remove_without_cursor(path, unlink);
    }
    let renamed = name == active_name;
    // Compensation restores the cursor as published, before any retirement.
    let mut original = before_retirement.unwrap_or_else(|| state.clone());
    let index = match matched {
        Some(index) => {
            if renamed {
                original.journals[index].segment = active_name.clone();
            }
            index
        }
        // Undelivered bytes the cursor has not adopted yet. Adopt them under
        // a fresh generation so the gap below names them.
        None => {
            let fingerprint_len = (len as usize).min(FINGERPRINT_BYTES) as u8;
            let fingerprint = fingerprint(&mut source, fingerprint_len as usize)?;
            register_journal(
                &mut state,
                name.to_owned(),
                identity.0,
                identity.1,
                fingerprint,
                fingerprint_len,
                len,
            )?;
            state.journals.len() - 1
        }
    };
    let active = path.with_file_name(&active_name);
    let mut target = path.to_owned();
    let mut delivery = LocalAuditDelivery {
        active,
        state_path,
        state,
        fenced: false,
        state_limit: MAX_STATE_BYTES,
    };
    // Clear only an interrupted pre-commit state write, as open() does.
    match fs::remove_file(delivery.state_path.with_extension("json.tmp")) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if renamed {
        // Bound probing rather than walking the account directory under local
        // admission. A collision defers this source; other files still expire.
        let start = (delivery.state.next_generation % 1_000_000) as u32;
        target = (0..16)
            .map(|offset| {
                path.with_file_name(format!(
                    "{stem}-seg{:06}.jsonl",
                    (start + offset) % 1_000_000
                ))
            })
            .find(|candidate| {
                fs::symlink_metadata(candidate).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if let Err(error) = commit_rename(path, &target) {
            // A directory-sync failure may follow the applied rename.
            if target.exists() {
                let _ = commit_rename(&target, path);
            }
            return Err(error);
        }
    }
    let result = (|| {
        let journal = &mut delivery.state.journals[index];
        journal.segment = target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("invalid sealed source"))?
            .to_owned();
        journal.observed_len = len;
        journal.change_time = change_time;
        journal.fingerprint_len = len.min(FINGERPRINT_BYTES as u64) as u8;
        journal.fingerprint = fingerprint(&mut source, journal.fingerprint_len as usize)?;
        if !delivered {
            // Retention is about to destroy the unaccepted extent: record it
            // as lost and advance past it, as a skipped record does, so the
            // absent file later retires without a second, generic gap.
            let gap = DeliveryGap {
                generation: journal.generation,
                segment: journal.segment.clone(),
                start: journal
                    .prepared
                    .as_ref()
                    .map_or(journal.acknowledged, |p| p.start),
                end: Some(len),
                reason: GapReason::ExpiredUndelivered,
            };
            journal.acknowledged = len;
            journal.prepared = None;
            journal.blocked = None;
            journal.split_records = None;
            journal.split_until = None;
            append_gap(&mut delivery.state, gap);
        }
        // This publication is the retirement intent: immutable closed source,
        // exact final byte length, and the ACK/prepared range or the gap that
        // replaces it. Crash at any later point leaves either that closed
        // file or its absence.
        publish(&mut delivery)?;
        match unlink(&target) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    })();
    if let Err(error) = result {
        // Restore cursor authority before making an active filename adoptable
        // again. If compensation cannot commit, keep the sealed inode intact;
        // a later discovery/retry can reconcile it without losing bytes.
        delivery.state = original;
        let _ = fs::remove_file(delivery.state_path.with_extension("json.tmp"));
        if delivery.publish_inner().is_ok() && renamed {
            let _ = commit_rename(&target, path);
        }
        return Err(error);
    }
    // The source is gone. Retire its journal as discovery would, so a cursor
    // that delivery no longer reads does not grow with every expired file.
    // Best effort: discovery reaches the same state if this write fails.
    let journal = &mut delivery.state.journals[index];
    journal.missing = true;
    journal.prepared = None;
    drop_retired(&mut delivery.state);
    let _ = delivery.publish_inner();
    result
}

/// Drop retired journals that no recorded gap names, as discovery does.
fn drop_retired(state: &mut State) {
    let named: std::collections::HashSet<_> = state.gaps.iter().map(|gap| gap.generation).collect();
    state
        .journals
        .retain(|journal| !journal.missing || named.contains(&journal.generation));
}

/// The live journal with this file's identity. Callers confirm it still
/// describes these bytes: by head fingerprint, or by name and modification
/// time when they do not open the file.
fn find_journal(state: &State, identity: (u64, u64)) -> Option<usize> {
    state
        .journals
        .iter()
        .position(|j| !j.missing && (j.device, j.inode) == identity)
}

/// What the cursor shows for one source of its own family, given the journal
/// that tracks it.
fn classify(
    state: &State,
    matched: Option<usize>,
    segment_index: Option<u32>,
    len: u64,
    change_time: u64,
) -> SourceDelivery {
    match matched.map(|index| &state.journals[index]) {
        Some(journal) => {
            if journal.prepared.is_none()
                && journal.observed_len == len
                && journal.acknowledged == len
            {
                SourceDelivery::Delivered
            } else {
                SourceDelivery::Undelivered
            }
        }
        None if len == 0 => SourceDelivery::Delivered,
        // An overflow gap already covers sealed segments it stopped tracking.
        None if state
            .overflow_floor
            .zip(segment_index)
            .is_some_and(|(floor, index)| {
                index <= floor && change_time <= state.overflow_floor_change_time
            }) =>
        {
            SourceDelivery::Untracked
        }
        None => SourceDelivery::Undelivered,
    }
}

/// The cursor's bytes, or `None` when the account never configured delivery.
fn read_cursor(state_dir: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(state_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Ok(meta) if meta.is_dir() => {}
        _ => return Err(invalid("invalid delivery state directory")),
    }
    let state_path = state_dir.join("local-delivery.json");
    match fs::symlink_metadata(&state_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(meta) if meta.is_file() => read_private_file(&state_path).map(Some),
        _ => Err(invalid("invalid delivery state file")),
    }
}

/// The cursor, if it governs `active_name`'s source family. A version 1
/// cursor did not record its source, so only its journals' names show it.
fn decode_for_family(bytes: &[u8], active_name: &str) -> io::Result<Option<State>> {
    let version = cursor_version(bytes)?;
    let state = decode_state(bytes, active_name)?;
    let stem = active_name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid source name"))?;
    let governs = if version == 1 {
        state
            .journals
            .iter()
            .any(|j| j.segment == active_name || sealed_index(stem, &j.segment).is_some())
    } else {
        state.source == active_name
    };
    if !governs {
        return Ok(None);
    }
    check_header(&state)?;
    validate_state(&state, active_name)?;
    Ok(Some(state))
}

fn cursor_version(bytes: &[u8]) -> io::Result<u8> {
    #[derive(Deserialize)]
    struct Header {
        version: u8,
    }
    Ok(serde_json::from_slice::<Header>(bytes)
        .map_err(|_| invalid("corrupt delivery cursor"))?
        .version)
}

/// The active recorder name a source belongs to, and its segment index.
fn source_family(path: &Path) -> io::Result<(String, Option<u32>)> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid source name"))?;
    let stem = name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid source name"))?;
    if let Some((base, _)) = stem.rsplit_once("-seg")
        && let Some(index) = sealed_index(base, name)
    {
        return Ok((format!("{base}.jsonl"), Some(index)));
    }
    Ok((name.to_owned(), None))
}

fn remove_without_cursor(
    path: &Path,
    unlink: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<bool> {
    match unlink(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
