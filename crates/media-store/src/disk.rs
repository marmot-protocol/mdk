//! Free-disk admission. The app supplies the policy (its configured reserve);
//! the store measures the volume and compares. There is no byte budget for
//! retained media: free disk is the only limit (mdk#2314).

use std::path::Path;

/// How much free space must remain on the volume after a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskPolicy {
    /// Bytes the account keeps free for everything else on the device.
    pub reserve_bytes: u64,
}

/// The outcome of an admission check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    /// Not enough room. `headroom` is the free space beyond the reserve the
    /// work needs: retry once the volume has that much plus the reserve.
    StorageFull {
        headroom: u64,
    },
}

impl DiskPolicy {
    /// Admits work that will still write `needed` bytes on a volume with
    /// `free` bytes available.
    pub fn admit(&self, free: u64, needed: u64) -> Admission {
        if free >= self.reserve_bytes.saturating_add(needed) {
            Admission::Admitted
        } else {
            Admission::StorageFull { headroom: needed }
        }
    }

    /// Bytes a download of a `body`-byte attachment still writes when
    /// `checkpointed` bytes of its wire checkpoint are already on disk: the
    /// rest of the checkpoint, then the store file published from it. Every
    /// download disk check uses this one rule, with `checkpointed` as large
    /// as the caller can vouch for. Never less than the store file.
    pub fn download_need(body: u64, checkpointed: u64) -> u64 {
        body.saturating_mul(2)
            .saturating_sub(checkpointed)
            .max(body)
    }

    /// The inverse of [`Self::download_need`]: the fewest checkpointed bytes
    /// with which a download of `body` bytes still writes at most
    /// `available`, or `None` when even a complete checkpoint leaves too
    /// little for the store file. The need falls as the checkpoint grows, so
    /// every larger checkpoint fits too. For filtering many downloads by one
    /// threshold, as readmission does.
    pub fn checkpoint_needed(body: u64, available: u64) -> Option<u64> {
        (available >= body).then(|| body.saturating_mul(2).saturating_sub(available))
    }
}

/// Free bytes on the volume holding `path`.
pub fn free_space(path: &Path) -> std::io::Result<u64> {
    fs4::available_space(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_keeps_the_reserve_free() {
        let policy = DiskPolicy { reserve_bytes: 100 };
        let needed = DiskPolicy::download_need(50, 0);
        assert_eq!(needed, 100);
        assert_eq!(policy.admit(200, needed), Admission::Admitted);
        assert_eq!(
            policy.admit(199, needed),
            Admission::StorageFull { headroom: 100 }
        );
    }

    #[test]
    fn the_checkpoint_threshold_is_exactly_the_need_inverted() {
        for body in [0, 1, 7, 50, 1 << 20] {
            for available in [0, 1, body / 2, body, body + 3, 2 * body, 3 * body] {
                for checkpointed in [0, 1, body / 3, body, 2 * body, 3 * body] {
                    let fits = DiskPolicy::download_need(body, checkpointed) <= available;
                    let threshold = DiskPolicy::checkpoint_needed(body, available);
                    assert_eq!(
                        fits,
                        threshold.is_some_and(|needed| checkpointed >= needed),
                        "body {body} available {available} checkpointed {checkpointed}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_saved_checkpoint_lowers_the_need_to_the_store_file() {
        assert_eq!(DiskPolicy::download_need(50, 20), 80);
        assert_eq!(DiskPolicy::download_need(50, 50), 50);
        assert_eq!(DiskPolicy::download_need(50, 1 << 40), 50);
    }
}
