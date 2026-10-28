//! Atomic, byte-preserving expiry of local JSONL records.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Remove records strictly older than `cutoff_ms` (Unix milliseconds) from a
/// closed JSONL file. Recent records keep their exact original bytes. Unknown
/// or incomplete rows are preserved. The caller must exclude live writers and
/// fence outstanding delivery attempts before changing their source files.
/// Returns whether the file changed; an empty result removes the file.
pub fn prune_jsonl_file_before(path: &Path, cutoff_ms: u64) -> io::Result<bool> {
    let Some((_file, len)) = retained_file(path, cutoff_ms)? else {
        return Ok(false);
    };
    if len == 0 {
        fs::remove_file(path)?;
    }
    Ok(true)
}

/// Replace atomically, returning the new append handle only when rows expired.
/// Every fallible preparation precedes rename; errors leave the source intact.
pub(super) fn retained_file(path: &Path, cutoff_ms: u64) -> io::Result<Option<(File, u64)>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular audit file",
        ));
    }
    let source = File::open(path)?;
    let staged = path.with_extension("jsonl-retention");
    // A previous interrupted pass may have left a private temporary file.
    match fs::remove_file(&staged) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let result = (|| {
        let mut writer = None;
        let mut reader = BufReader::new(source);
        let mut line = Vec::new();
        let mut scanned = 0;
        let mut oversized_tail = false;
        loop {
            line.clear();
            // Match v5's body ceiling. Larger historical/invalid rows stream
            // through unchanged rather than allocating their entire body.
            if (&mut reader)
                .take((crate::v5::MAX_BODY_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)?
                == 0
            {
                break;
            }
            // Both v4's JSON number and v5's decimal string describe the same
            // wall clock. Do not reserialize: delivery hashes original bodies.
            let expired = !oversized_tail
                && line.ends_with(b"\n")
                && serde_json::from_slice::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|row| match &row["wall_time_ms"] {
                        serde_json::Value::Number(number) => number.as_i64(),
                        serde_json::Value::String(value) => value.parse::<i64>().ok(),
                        _ => None,
                    })
                    .is_some_and(|timestamp| i128::from(timestamp) < i128::from(cutoff_ms));
            if expired {
                if writer.is_none() {
                    let mut staged_writer =
                        BufWriter::new(fs_private::create_new_private(&staged)?);
                    // Allocate/write a replacement only after finding expired
                    // bytes. An unchanged recent log needs no extra disk space.
                    io::copy(&mut File::open(path)?.take(scanned), &mut staged_writer)?;
                    writer = Some(staged_writer);
                }
            } else if let Some(writer) = &mut writer {
                writer.write_all(&line)?;
            }
            scanned += line.len() as u64;
            oversized_tail = !line.ends_with(b"\n");
        }
        let Some(mut writer) = writer else {
            return Ok(None);
        };
        writer.flush()?;
        writer.get_ref().sync_all()?;
        // Open the replacement for append before committing the rename, so a
        // live recorder can adopt it without another fallible operation.
        let file = fs_private::open_private_append(&staged)?;
        let len = file.metadata()?.len();
        fs::rename(&staged, path)?;
        Ok(Some((file, len)))
    })();
    let _ = fs::remove_file(staged);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_keeps_boundary_recent_unknown_and_partial_rows_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-test.jsonl");
        let retained = b"{ \"wall_time_ms\": \"100\", \"extra\": 1 }\n{\"wall_time_ms\":101}\ninvalid\n{\"other\":1}\n{\"wall_time_ms\":1}";
        let mut original = b"{\"wall_time_ms\":1}\n{\"wall_time_ms\":\"-1\"}\n".to_vec();
        original.extend_from_slice(retained);
        fs::write(&path, original).unwrap();
        assert!(prune_jsonl_file_before(&path, 100).unwrap());
        assert_eq!(fs::read(&path).unwrap(), retained);
        assert!(!prune_jsonl_file_before(&path, 100).unwrap());
    }

    #[test]
    fn retention_removes_a_fully_expired_closed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-test.jsonl");
        fs::write(&path, b"{\"wall_time_ms\":1}\n").unwrap();
        assert!(prune_jsonl_file_before(&path, 100).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn retention_of_live_shared_recorder_preserves_session_sequence_and_writer() {
        use crate::{AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder, SharedRecorder};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-test-v5.jsonl");
        let recorder = SharedRecorder::new(Box::new(
            JsonlRecorder::open_v5_with_account_ref(
                &path,
                "a".repeat(32),
                None,
                crate::v5::Producer {
                    mdk_revision: None,
                    build_profile: crate::v5::BuildProfile::Debug,
                    platform: crate::v5::Platform::Other,
                    host_build: None,
                },
            )
            .unwrap(),
        ));
        let rows: Vec<serde_json::Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let last = rows.last().unwrap();
        let segment = dir.path().join("audit-test-v5-seg000001.jsonl");
        fs::write(&segment, b"{\"wall_time_ms\":1}\n").unwrap();
        recorder.prune_before(u64::MAX).unwrap();
        assert!(!segment.exists());
        assert!(fs::read(&path).unwrap().is_empty());
        recorder.clone().record(AuditRecord::new(
            None,
            AuditEventKind::RecorderHealth {
                serialization_failures: 0,
                write_failures: 0,
                flush_failures: 0,
            },
        ));
        let body = fs::read(&path).unwrap();
        crate::v5::Record::from_json(body.strip_suffix(b"\n").unwrap()).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(after["session_id"], last["session_id"]);
        assert_eq!(
            after["seq"].as_str().unwrap().parse::<u64>().unwrap(),
            last["seq"].as_str().unwrap().parse::<u64>().unwrap() + 1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn retention_failure_preserves_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-test.jsonl");
        let body = b"{\"wall_time_ms\":1}\n";
        fs::write(&path, body).unwrap();
        fs::create_dir(path.with_extension("jsonl-retention")).unwrap();
        assert!(prune_jsonl_file_before(&path, 100).is_err());
        assert_eq!(fs::read(path).unwrap(), body);
    }

    #[test]
    fn retention_streams_oversized_rows_and_keeps_a_recent_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-test.jsonl");
        let mut retained = b"{\"wall_time_ms\":100}\n".to_vec();
        retained.extend(vec![b'x'; crate::v5::MAX_BODY_BYTES * 3]);
        retained.push(b'\n');
        let mut body = retained.clone();
        body.extend_from_slice(b"{\"wall_time_ms\":1}\n");
        fs::write(&path, body).unwrap();
        assert!(prune_jsonl_file_before(&path, 100).unwrap());
        assert_eq!(fs::read(path).unwrap(), retained);
    }
}
