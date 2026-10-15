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

    /// Bytes a download of a `body`-byte attachment occupies at its peak:
    /// its wire checkpoint plus the store file being published from it.
    pub fn download_bytes(body: u64) -> u64 {
        body.saturating_mul(2)
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
        let needed = DiskPolicy::download_bytes(50);
        assert_eq!(needed, 100);
        assert_eq!(policy.admit(200, needed), Admission::Admitted);
        assert_eq!(
            policy.admit(199, needed),
            Admission::StorageFull { headroom: 100 }
        );
    }
}
