//! Retire a known closed inode before expiry, without weakening generic loss detection.

use super::*;

/// The caller excludes every writer of this file and fences this directory's
/// delivery work. Source bytes never change. The only irreversible operation
/// (unlink) runs after the closed alias and final observed length are durable.
pub fn expire_closed_source(path: &Path, state_dir: &Path) -> io::Result<bool> {
    expire_with(
        path,
        state_dir,
        |target| fs::remove_file(target),
        |delivery| delivery.publish(),
    )
}

pub(super) fn expire_with(
    path: &Path,
    state_dir: &Path,
    unlink: impl FnOnce(&Path) -> io::Result<()>,
    publish: impl FnOnce(&mut LocalAuditDelivery) -> io::Result<()>,
) -> io::Result<bool> {
    let state_path = state_dir.join("local-delivery.json");
    let state_metadata = match fs::symlink_metadata(state_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return remove_without_cursor(path, unlink);
        }
        Ok(meta) if meta.is_dir() => fs::symlink_metadata(&state_path),
        _ => return Err(invalid("invalid delivery state directory")),
    };
    match state_metadata {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return remove_without_cursor(path, unlink);
        }
        Ok(meta) if meta.is_file() => {}
        _ => return Err(invalid("invalid delivery state file")),
    }
    let mut source = open_source(path)?;
    let identity = file_identity(&source)?;
    let len = source.metadata()?.len();
    let state: State = serde_json::from_slice(&read_private_file(&state_path)?)
        .map_err(|_| invalid("corrupt delivery cursor"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid source name"))?;
    let stem = name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid source name"))?;
    let stem = match stem.rsplit_once("-seg") {
        Some((base, index)) if index.len() >= 6 && index.parse::<u32>().is_ok() => base,
        _ => stem,
    };
    let active_name = format!("{stem}.jsonl");
    let segment_prefix = format!("{stem}-seg");
    // One directory can retain files from a previous device identity. Its
    // current cursor has no authority over a different source family.
    if !state
        .journals
        .iter()
        .any(|j| j.segment == active_name || j.segment.starts_with(&segment_prefix))
    {
        return remove_without_cursor(path, unlink);
    }
    if state.version != 1
        || state.destination.is_empty()
        || state.destination.len() > 256
        || state.next_generation == 0
    {
        return Err(invalid("incompatible delivery cursor"));
    }
    validate_state(&state, &active_name)?;
    let Some(index) = state
        .journals
        .iter()
        .position(|j| !j.missing && (j.device, j.inode) == identity)
    else {
        return remove_without_cursor(path, unlink);
    };
    let journal = &state.journals[index];
    // Reused identities or externally changed sources retain the ordinary
    // conservative missing-source behavior. Never bless those bytes as ACKed.
    if len < journal.observed_len
        || len < journal.fingerprint_len as u64
        || fingerprint(&mut source, journal.fingerprint_len as usize)? != journal.fingerprint
    {
        return remove_without_cursor(path, unlink);
    }
    // An unchanged sealed alias already has a durable final-length proof.
    // Ordinary expiry needs no cursor rewrite or extra staging space.
    if name != active_name && journal.segment == name && journal.observed_len == len {
        return remove_without_cursor(path, unlink);
    }
    let mut original = state.clone();
    if name == active_name {
        original.journals[index].segment = active_name.clone();
    }
    let active = path.with_file_name(&active_name);
    let mut target = path.to_owned();
    let renamed = name == active_name;
    let mut delivery = LocalAuditDelivery {
        active,
        state_path,
        state,
        fenced: false,
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
        journal.fingerprint_len = len.min(FINGERPRINT_BYTES as u64) as u8;
        journal.fingerprint = fingerprint(&mut source, journal.fingerprint_len as usize)?;
        // This publication is the retirement intent: immutable closed source,
        // exact final byte length, and unchanged ACK/prepared range. Crash at
        // any later point leaves either that closed file or its absence.
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
    result
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
