//! Attachment uploads in flight per group (mdk#2158). An upload's media key is
//! bound to the epoch it was encrypted under, so while one is in flight this
//! device holds its own due self-update for that group: a rotation would leave
//! the finished upload unsendable after its last byte.

use cgka_traits::GroupId;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long one upload may hold its group's self-update, measured on the
/// monotonic clock so a wall-clock change cannot stretch it. Automatic rotation
/// has nobody to ask, so a stuck or very long upload can delay it but never
/// suppress it.
pub(crate) const UPLOAD_SELF_UPDATE_HOLD: Duration = Duration::from_secs(60 * 60);

/// Uploads in flight, each with the group it belongs to and when it started.
#[derive(Clone, Default)]
pub(crate) struct UploadEpochHolds {
    inner: Arc<Mutex<Uploads>>,
}

#[derive(Default)]
struct Uploads {
    next_id: u64,
    in_flight: Vec<(u64, GroupId, Instant)>,
}

impl UploadEpochHolds {
    /// Record an upload for `group` that started at `started`. It holds the
    /// group's self-update until the returned guard drops.
    pub(crate) fn hold(&self, group: GroupId, started: Instant) -> UploadEpochHold {
        let mut uploads = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = uploads.next_id;
        uploads.next_id = uploads.next_id.wrapping_add(1);
        uploads.in_flight.push((id, group, started));
        UploadEpochHold {
            uploads: Arc::clone(&self.inner),
            id,
        }
    }

    /// Groups with an upload in flight that started less than
    /// [`UPLOAD_SELF_UPDATE_HOLD`] before `now`, each once.
    pub(crate) fn held_groups(&self, now: Instant) -> Vec<GroupId> {
        let uploads = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut held: Vec<GroupId> = Vec::new();
        for (_, group, started) in &uploads.in_flight {
            if now.saturating_duration_since(*started) < UPLOAD_SELF_UPDATE_HOLD
                && !held.contains(group)
            {
                held.push(group.clone());
            }
        }
        held
    }
}

/// One upload's hold on its group's self-update, released when it drops:
/// after the upload is sent or admitted, fails, is cancelled or is abandoned.
pub(crate) struct UploadEpochHold {
    uploads: Arc<Mutex<Uploads>>,
    id: u64,
}

impl Drop for UploadEpochHold {
    fn drop(&mut self) {
        self.uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_flight
            .retain(|(id, _, _)| *id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(byte: u8) -> GroupId {
        GroupId::new(vec![byte; 16])
    }

    /// A group stays held while any of its uploads is in flight, once, and is
    /// released when the last one drops.
    #[test]
    fn a_group_is_held_while_any_of_its_uploads_is_in_flight() {
        let base = Instant::now();
        let at = |ms: u64| base + Duration::from_millis(ms);
        let holds = UploadEpochHolds::default();
        assert!(holds.held_groups(at(0)).is_empty());
        let first = holds.hold(group(1), at(0));
        let second = holds.hold(group(1), at(10));
        let other = holds.hold(group(2), at(20));
        assert_eq!(holds.held_groups(at(30)), vec![group(1), group(2)]);
        drop(first);
        assert_eq!(holds.held_groups(at(30)), vec![group(1), group(2)]);
        drop(second);
        assert_eq!(holds.held_groups(at(30)), vec![group(2)]);
        drop(other);
        assert!(holds.held_groups(at(30)).is_empty());
    }

    /// An upload holds its group for at most the bound of elapsed monotonic
    /// time, so a stuck upload can delay rotation but never suppress it, and a
    /// wall-clock change cannot stretch the hold.
    #[test]
    fn an_upload_holds_its_group_only_within_the_bound() {
        let started = Instant::now();
        let holds = UploadEpochHolds::default();
        let _upload = holds.hold(group(1), started);
        assert_eq!(
            holds.held_groups(started + UPLOAD_SELF_UPDATE_HOLD - Duration::from_millis(1)),
            vec![group(1)]
        );
        assert!(
            holds
                .held_groups(started + UPLOAD_SELF_UPDATE_HOLD)
                .is_empty()
        );
        // A reading before the start (never produced by a monotonic clock, but
        // harmless) holds rather than panics.
        assert_eq!(holds.held_groups(started), vec![group(1)]);
    }
}
