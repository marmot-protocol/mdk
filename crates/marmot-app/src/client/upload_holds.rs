//! Attachment uploads in flight per group (mdk#2158). An upload's media key is
//! bound to the epoch it was encrypted under, so while one is in flight this
//! device holds its own due periodic self-update for that group: a rotation
//! would leave the finished upload unsendable after its last byte.

use cgka_traits::GroupId;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a group may stay held from the moment its hold began, measured on
/// the monotonic clock so a wall-clock change cannot stretch it. Automatic
/// rotation has nobody to ask, so stuck, very long or back-to-back uploads can
/// delay it but never suppress it.
pub(crate) const UPLOAD_SELF_UPDATE_HOLD: Duration = Duration::from_secs(2 * 60 * 60);

/// How long a finished upload that is not sent with it keeps holding its
/// group: long enough for token admission, or a host's immediate send, to
/// reference it from the epoch it was encrypted under.
pub(crate) const UPLOAD_ADMISSION_GRACE: Duration = Duration::from_secs(60);

/// Uploads holding their groups' self-updates. Each [`crate::AppClient`] keeps
/// its own, and its maintenance sweep consults only that one.
#[derive(Clone, Default)]
pub(crate) struct UploadEpochHolds {
    inner: Arc<Mutex<Uploads>>,
}

#[derive(Default)]
struct Uploads {
    next_id: u64,
    /// Uploads in flight, each with its group.
    in_flight: Vec<(u64, GroupId)>,
    /// Finished uploads waiting to be sent, each holding its group until the
    /// instant given.
    lingering: Vec<(GroupId, Instant)>,
    /// When each held group's hold began. It lasts while uploads for the group
    /// overlap or follow within their grace, and ends once nothing holds it.
    episodes: Vec<(GroupId, Instant)>,
}

impl Uploads {
    /// Forget lapsed graces and the episodes of groups nothing holds any more.
    fn prune(&mut self, now: Instant) {
        self.lingering.retain(|(_, until)| *until > now);
        let Self {
            in_flight,
            lingering,
            episodes,
            ..
        } = self;
        episodes.retain(|(group, _)| {
            in_flight.iter().any(|(_, held)| held == group)
                || lingering.iter().any(|(held, _)| held == group)
        });
    }
}

impl UploadEpochHolds {
    /// Record an upload for `group` starting at `now`. It holds the group's
    /// self-update until the returned guard drops or lingers.
    pub(crate) fn hold(&self, group: GroupId, now: Instant) -> UploadEpochHold {
        let mut uploads = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        uploads.prune(now);
        let id = uploads.next_id;
        uploads.next_id = uploads.next_id.wrapping_add(1);
        if !uploads.episodes.iter().any(|(held, _)| held == &group) {
            uploads.episodes.push((group.clone(), now));
        }
        uploads.in_flight.push((id, group));
        UploadEpochHold {
            uploads: Arc::clone(&self.inner),
            id,
        }
    }

    /// Groups an upload holds at `now`, each once: those with an upload in
    /// flight or within its grace whose hold began less than
    /// [`UPLOAD_SELF_UPDATE_HOLD`] before `now`.
    pub(crate) fn held_groups(&self, now: Instant) -> Vec<GroupId> {
        let mut uploads = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        uploads.prune(now);
        uploads
            .episodes
            .iter()
            .filter(|(_, began)| now.saturating_duration_since(*began) < UPLOAD_SELF_UPDATE_HOLD)
            .map(|(group, _)| group.clone())
            .collect()
    }
}

/// One upload's hold on its group's self-update, released when it drops:
/// after the upload is sent, fails, is cancelled or is abandoned.
pub(crate) struct UploadEpochHold {
    uploads: Arc<Mutex<Uploads>>,
    id: u64,
}

impl UploadEpochHold {
    /// Keep holding the group for [`UPLOAD_ADMISSION_GRACE`] after `now`: the
    /// upload finished but is sent separately.
    pub(crate) fn linger(self, now: Instant) {
        let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = uploads.in_flight.iter().position(|(id, _)| *id == self.id) {
            let (_, group) = uploads.in_flight.remove(index);
            uploads
                .lingering
                .push((group, now + UPLOAD_ADMISSION_GRACE));
        }
        drop(uploads);
    }
}

impl Drop for UploadEpochHold {
    fn drop(&mut self) {
        self.uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_flight
            .retain(|(id, _)| *id != self.id);
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

    /// A group is held for at most the bound from when its hold began, so a
    /// stuck upload can delay rotation but never suppress it, and a wall-clock
    /// change cannot stretch the hold.
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

    /// Uploads that overlap one another share one bound, so back-to-back
    /// uploads cannot hold a group indefinitely. Once nothing holds the group,
    /// the next upload starts a new hold.
    #[test]
    fn overlapping_uploads_share_one_bound() {
        let started = Instant::now();
        let hour = Duration::from_secs(60 * 60);
        let holds = UploadEpochHolds::default();
        let first = holds.hold(group(1), started);
        let second = holds.hold(group(1), started + hour);
        drop(first);
        assert_eq!(
            holds.held_groups(started + UPLOAD_SELF_UPDATE_HOLD - Duration::from_millis(1)),
            vec![group(1)]
        );
        assert!(
            holds
                .held_groups(started + UPLOAD_SELF_UPDATE_HOLD)
                .is_empty()
        );
        drop(second);
        let later = started + UPLOAD_SELF_UPDATE_HOLD + hour;
        let _third = holds.hold(group(1), later);
        assert_eq!(holds.held_groups(later), vec![group(1)]);
    }

    /// A finished upload sent separately keeps its group held through the
    /// grace, and an upload that starts within it continues the same hold.
    #[test]
    fn a_lingering_upload_holds_its_group_through_the_grace() {
        let started = Instant::now();
        let holds = UploadEpochHolds::default();
        holds.hold(group(1), started).linger(started);
        assert_eq!(
            holds.held_groups(started + UPLOAD_ADMISSION_GRACE - Duration::from_millis(1)),
            vec![group(1)]
        );
        assert!(
            holds
                .held_groups(started + UPLOAD_ADMISSION_GRACE)
                .is_empty()
        );

        let again = started + UPLOAD_SELF_UPDATE_HOLD;
        holds.hold(group(2), again).linger(again);
        let _next = holds.hold(group(2), again + Duration::from_secs(1));
        assert!(
            holds
                .held_groups(again + UPLOAD_SELF_UPDATE_HOLD)
                .is_empty()
        );
    }
}
